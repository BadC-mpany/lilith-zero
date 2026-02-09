import asyncio
import os
import sys
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import StructuredTool
from lilith_zero import Lilith, PolicyViolationError

load_dotenv()

LILITH_ZERO_BINARY = os.path.abspath("../../lilith-zero/target/release/lilith-zero.exe")
POLICY_PATH = os.path.abspath("policy.yaml")
UPSTREAM_CMD = f"{sys.executable} -u upstream.py"

if not os.path.exists(LILITH_ZERO_BINARY):
    sys.exit(f"Binary not found: {LILITH_ZERO_BINARY}")

async def main():
    print(f"Lilith Agent Active.\nBinary: {LILITH_ZERO_BINARY}\nPolicy: {POLICY_PATH}\n")
    
    async with Lilith(upstream=UPSTREAM_CMD, binary=LILITH_ZERO_BINARY, policy=POLICY_PATH) as sentinel:
        # Tool Wrappers
        async def safe_calc(expression: str) -> str:
            return await sentinel.call_tool("calculator", {"expression": expression})

        async def safe_read(customer_id: str) -> str:
            return await sentinel.call_tool("read_customer_data", {"customer_id": customer_id})

        async def safe_export(data: str) -> str:
            return await sentinel.call_tool("export_analytics", {"data": data})

        async def safe_maint(region: str) -> str:
            return await sentinel.call_tool("system_maintenance", {"region": region})

        async def safe_nuke() -> str:
            return await sentinel.call_tool("nuke_database", {})

        tools = [
            StructuredTool.from_function(func=None, coroutine=safe_calc, name="calculator", description="Math calculation"),
            StructuredTool.from_function(func=None, coroutine=safe_read, name="read_customer_data", description="Read customer data"),
            StructuredTool.from_function(func=None, coroutine=safe_export, name="export_analytics", description="Export data"),
            StructuredTool.from_function(func=None, coroutine=safe_maint, name="system_maintenance", description="System maintenance"),
            StructuredTool.from_function(func=None, coroutine=safe_nuke, name="nuke_database", description="Nuke DB"),
        ]

        llm = ChatOpenAI(
            model="qwen/qwen3-next-80b-a3b-instruct",
            temperature=0,
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv("OPENROUTER_API_KEY")
        )
        llm_with_tools = llm.bind_tools(tools)
        
        print("Ready. Type 'quit' to exit.")
        
        while True:
            try:
                user_in = input("User: ").strip()
                if user_in.lower() in ("quit", "exit"): break
                
                msgs = [HumanMessage(content=user_in)]
                ai_msg = await llm_with_tools.ainvoke(msgs)
                msgs.append(ai_msg)

                if ai_msg.tool_calls:
                    print(f"Agent calls: {[tc['name'] for tc in ai_msg.tool_calls]}")
                    for tc in ai_msg.tool_calls:
                        try:
                            tool = next(t for t in tools if t.name == tc["name"])
                            print(f"Lilith Executing: {tc['name']}...")
                            res = await tool.ainvoke(tc["args"])
                            print(f"Lilith Allowed: {res}")
                            msgs.append(ToolMessage(content=str(res), tool_call_id=tc["id"]))
                        except PolicyViolationError as e:
                            print(f"Lilith BLOCKED: {e}")
                            msgs.append(ToolMessage(content=f"Security Block: {e}", tool_call_id=tc["id"]))
                        except Exception as e:
                            print(f"Error: {e}")
                            msgs.append(ToolMessage(content=str(e), tool_call_id=tc["id"]))
                    
                    final = await llm_with_tools.ainvoke(msgs)
                    print(f"Assistant: {final.content}")
                else:
                    print(f"Assistant: {ai_msg.content}")

            except KeyboardInterrupt: break
            except Exception as e: print(f"Loop error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
