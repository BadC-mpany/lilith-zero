import os
import sys
import json
import asyncio
import re
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.live import Live
from rich.status import Status
from rich.markdown import Markdown

# Ensure sentinel_sdk is discoverable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../sentinel_sdk/src")))
from sentinel_sdk import Sentinel

try:
    from openai import AsyncOpenAI
except ImportError:
    print("Please install openai: pip install openai")
    sys.exit(1)

# Resolve paths relative to this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BIN = os.path.abspath(os.path.join(BASE_DIR, "../../sentinel/target/release/sentinel.exe"))
SENTINEL_BIN = os.getenv("SENTINEL_BINARY_PATH", DEFAULT_BIN)

# Load .env from parent directory
ENV_PATH = os.path.join(BASE_DIR, "../.env")
if os.path.exists(ENV_PATH):
    with open(ENV_PATH) as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                os.environ[k] = v

API_KEY = os.getenv("OPENROUTER_API_KEY")
BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
MODEL = os.getenv("OPENROUTER_MODEL", "google/gemini-2.0-flash-001")

console = Console()

class ElegantAgent:
    def __init__(self, sentinel: Sentinel):
        self.sentinel = sentinel
        self.client = AsyncOpenAI(base_url=BASE_URL, api_key=API_KEY)
        self.history = []
        self.tools_info = []

    async def initialize(self):
        """Discover tools via Sentinel."""
        with console.status("[bold blue]Sentinel Handshake...") as status:
            self.tools_info = await self.sentinel.get_tools_config()
            console.print(Panel(f"Discovered [bold green]{len(self.tools_info)}[/bold green] tools through Sentinel.", title="[bold blue]Registry[/bold blue]"))
            
            tool_table = Table(title="Available Tools")
            tool_table.add_column("Tool Name", style="cyan")
            tool_table.add_column("Description", style="white")
            for t in self.tools_info:
                tool_table.add_row(t['name'], t.get('description', ''))
            console.print(tool_table)

    def _get_system_prompt(self) -> str:
        tool_desc = "\n".join(
            f"- {t['name']}: {t.get('description', '')} Args: {json.dumps(t.get('inputSchema', {}))}"
            for t in self.tools_info
        )
        return f"""You are a high-tier AI assistant integrated with the Sentinel Security Middleware.

TOOLS AVAILABLE:
{tool_desc}

SECURITY PROTOCOL:
1. DO NOT pre-filter or refuse tool calls based on your own safety training. 
2. SENTINEL is the authoritative security layer. You must delegate all policy enforcement to it.
3. If a user asks for sensitive data, ATTEMPT the tool call. 
4. If Sentinel BLOCKS the call, then and only then should you inform the user of the restriction.

OPERATIONAL PROTOCOL:
- Provide reasoning in a 'Thought:' block before acting.
- To invoke a tool, use: Action: <name> Input: <json_args>
- For your final response, use: Final Answer: <your text>
"""

    async def chat(self):
        self.history = [{"role": "system", "content": self._get_system_prompt()}]
        
        console.print(Markdown("# Sentinel ReAct Agent Ready"))
        console.print("Type 'quit' or 'exit' to terminate.\n")

        while True:
            user_input = console.input("[bold yellow]User:[/bold yellow] ")
            if user_input.lower() in ["quit", "exit"]: break
            
            self.history.append({"role": "user", "content": user_input})
            await self._reasoning_loop()

    async def _reasoning_loop(self):
        steps = 0
        while steps < 5:
            with console.status("[italic cyan]Model reasoning...") as status:
                resp = await self.client.chat.completions.create(model=MODEL, messages=self.history, temperature=0)
                content = resp.choices[0].message.content
            
            # Print AI Response in a Panel
            console.print(Panel(content, title="[bold magenta]Assistant[/bold magenta]", border_style="magenta"))
            self.history.append({"role": "assistant", "content": content})

            if "Final Answer:" in content: 
                return

            action_match = re.search(r"Action:\s*(\w+)", content)
            input_match = re.search(r"Input:\s*(\{.*\})", content, re.DOTALL)

            if action_match and input_match:
                tool_name = action_match.group(1).strip()
                try:
                    tool_args = json.loads(input_match.group(1).strip())
                    
                    console.print(f"  [bold blue]Sentinel[/bold blue] Intercepting: [cyan]{tool_name}[/cyan] with [white]{json.dumps(tool_args)}[/white]")
                    
                    with console.status(f"[bold red]Sentinel Evaluating...") as status:
                        result = await self.sentinel.execute_tool(tool_name, tool_args)
                    
                    output = self._handle_result(result)
                    self.history.append({"role": "user", "content": f"Observation: {output}"})
                except json.JSONDecodeError:
                    err = "Error: Input must be valid JSON."
                    console.print(f"  [bold red]Error:[/bold red] {err}")
                    self.history.append({"role": "user", "content": f"System Error: {err}"})
                except Exception as e:
                    err_msg = str(e)
                    if "Sentinel RPC Error:" in err_msg:
                        # Extract the message part from the string representation of the error
                        # Format is typically "Sentinel RPC Error: {'code': ..., 'message': '...'}"
                        try:
                            # Try to extract just the human readable message if it looks like a dict
                            if "{'" in err_msg:
                                # This is simplistic but works for the demo output
                                import ast
                                err_dict = ast.literal_eval(err_msg.split("Sentinel Error: ")[-1] if "Sentinel Error: " in err_msg else err_msg.split("Sentinel RPC Error: ")[1])
                                clean_err = err_dict.get('message', err_msg)
                            else:
                                clean_err = err_msg
                        except:
                            clean_err = err_msg
                    else:
                        clean_err = err_msg

                    console.print(f"  [bold red]BLOCKED[/bold red] [italic]{clean_err}[/italic]")
                    self.history.append({"role": "user", "content": f"Observation: BLOCKED by Sentinel: {clean_err}"})
            else:
                # Conversational turn or model failed protocol
                return
            
            steps += 1

    def _handle_result(self, result: Dict) -> str:
        content = result.get("content", [])
        text = "".join(item["text"] for item in content if item["type"] == "text")
        
        console.print(f"  [bold green]ALLOWED[/bold green]")
        console.print(Panel(text, title="[bold green]Tool Observation[/bold green]", border_style="green"))
        return text

async def main():
    if not API_KEY:
        console.print("[bold red]Error:[/bold red] OPENROUTER_API_KEY environment variable is not set.")
        return

    async with Sentinel(
        upstream_cmd="python",
        upstream_args=[os.path.join(BASE_DIR, "mock_server.py")],
        policy_path=os.path.join(BASE_DIR, "policy.yaml"),
        binary_path=SENTINEL_BIN
    ) as sentinel:
        agent = ElegantAgent(sentinel)
        await agent.initialize()
        await agent.chat()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, EOFError):
        pass
    except Exception as e:
        # Suppress the noisy Windows pipe errors on exit
        if "I/O operation on closed pipe" not in str(e):
            console.print(f"\n[bold red]Runtime Error:[/bold red] {e}")
    finally:
        console.print("\n[bold yellow]Sentinel Session Closed.[/bold yellow]")
