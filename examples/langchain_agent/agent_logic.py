import os
import sys
import logging
import asyncio
import time
from typing import List, Dict, Any, AsyncGenerator

# Ensure sdk is in path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "sdk", "src"))

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, ToolMessage, SystemMessage, AIMessage
from langchain_core.tools import StructuredTool
from lilith_zero import Lilith
from lilith_zero.exceptions import PolicyViolationError

# Load Env
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

# Constants
LILITH_BIN = os.getenv("LILITH_ZERO_BINARY_PATH", os.path.join(PROJECT_ROOT, "lilith-zero/target/release/lilith-zero"))
POLICY_PATH = os.path.join(os.path.dirname(__file__), "policy.yaml")
MOCK_SERVER = os.path.join(os.path.dirname(__file__), "mock_server.py")
os.environ["POLICIES_YAML_PATH"] = POLICY_PATH

class AgentManager:
    def __init__(self):
        self.lilith = None
        self.llm = None
        self.tools = []
        self._initialized = False

    async def initialize(self):
        """Initialize Lilith and LLM."""
        if self._initialized: return
        
        if not os.path.exists(LILITH_BIN):
            raise FileNotFoundError(f"Binary not found: {LILITH_BIN}")
        
        self.lilith = Lilith(upstream=f"{sys.executable} -u {MOCK_SERVER}", binary=LILITH_BIN, policy=POLICY_PATH)
        # Manually enter context
        await self.lilith.__aenter__()

        # Define tools wrapper
        async def call_lilith(name, **kwargs):
            return await self.lilith.call_tool(name, kwargs)

        async def read_resource_file(path_suffix):
            uri = f"file:///{path_suffix.lstrip('/')}"
            # Let exceptions propagate (so they are caught as Blocks/Errors by Lilith middleware or main loop)
            res = await self.lilith.read_resource(uri)
            if 'contents' in res and len(res['contents']) > 0:
                return res['contents'][0]['text']
            return f"Error: No content found for {uri}"

        self.tools = [
            StructuredTool.from_function(func=None, coroutine=lambda q: call_lilith("web_search", query=q), name="web_search", description="Search the web for information"),
            StructuredTool.from_function(func=None, coroutine=lambda k: call_lilith("read_data", key=k), name="read_data", description="Read key-value data from the store"),
            StructuredTool.from_function(func=None, coroutine=lambda q: call_lilith("read_sql_db", query=q), name="read_sql_db", description="Execute SELECT queries on the SQL database"),
            StructuredTool.from_function(func=None, coroutine=lambda k, v: call_lilith("write_data", key=k, value=v), name="write_data", description="Write data to the store"),
            StructuredTool.from_function(func=None, coroutine=lambda c: call_lilith("delete_db", confirm=c), name="delete_db", description="Delete the entire database"),
            StructuredTool.from_function(func=None, coroutine=read_resource_file, name="read_file", description="Read a file resource. Available files: logs/system.log, confidential_data.txt, etc/config.json"),
        ]

        self.llm = ChatOpenAI(
            model=os.getenv("OPENROUTER_MODEL", "google/gemini-2.0-flash-001"),
            base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            api_key=os.getenv("OPENROUTER_API_KEY")
        ).bind_tools(self.tools)
        
        self._initialized = True

    async def run_turn(self, history: List[Any]) -> AsyncGenerator[Dict, None]:
        """Runs a turn. Yields dicts with 'type' ('log', 'message') and data."""
        try:
            # 1. First LLM call (Thought/Tool Request)
            ai_msg = await self.llm.ainvoke(history)
            
            # Yield initial thought if any
            if ai_msg.content:
                 yield {"type": "message", "role": "assistant", "content": ai_msg.content}
            
            history.append(ai_msg)

            if ai_msg.tool_calls:
                for tc in ai_msg.tool_calls:
                    start_time = time.perf_counter()
                    outcome = "Allowed"
                    error_reason = None
                    text = ""
                    
                    try:
                        tool = next(t for t in self.tools if t.name == tc["name"])
                        res = await tool.ainvoke(tc["args"])
                        
                        # Process result
                        text = "Tool executed successfully"
                        if isinstance(res, dict) and 'content' in res:
                            text = str(res['content'][0]['text'])
                        elif isinstance(res, str):
                            text = res
                        else:
                            text = str(res)
                        
                         # JSON fix (mock server specific)
                        try:
                            import json
                            parsed = json.loads(text)
                            if isinstance(parsed, list) and len(parsed) > 0 and 'text' in parsed[0]:
                                text = parsed[0]['text']
                        except:
                            pass

                    except PolicyViolationError as e:
                        outcome = "BLOCKED"
                        error_reason = str(e)
                        text = f"Error: {e}"
                        # Check if "Default Deny" pattern from propagate resource error
                    except Exception as e:
                        if "Default Deny" in str(e) or "Access to resource denied" in str(e):
                             outcome = "BLOCKED"
                             error_reason = str(e)
                        else:
                             outcome = "ERROR"
                             error_reason = str(e)
                        text = f"Error: {e}"

                    latency_ms = (time.perf_counter() - start_time) * 1000
                    
                    # Log event
                    log_entry = {
                        "tool": tc['name'],
                        "inputs": str(tc["args"]),
                        "status": outcome,
                        "latency_ms": latency_ms,
                        "reason": error_reason,
                        "output": text[:200] + "..." if len(text) > 200 else text,
                        "timestamp": time.strftime("%H:%M:%S")
                    }
                    yield {"type": "log", "data": log_entry}

                    # Append tool result to history
                    tm = ToolMessage(content=text, tool_call_id=tc["id"])
                    history.append(tm)
                
                # 2. Final LLM call (Response)
                final = await self.llm.ainvoke(history)
                history.append(final)
                yield {"type": "message", "role": "assistant", "content": final.content}
            
        except Exception as e:
            yield {"type": "error", "message": f"Critical Error: {str(e)}"}

    async def cleanup(self):
        if self.lilith:
            await self.lilith.__aexit__(None, None, None)
