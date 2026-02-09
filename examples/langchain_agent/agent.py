# Copyright 2026 BadCompany
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import os
import sys

# Ensure lilith_zero is discoverable
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "sdk", "src"))

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import StructuredTool
from lilith_zero import Lilith
from lilith_zero.exceptions import PolicyViolationError
from rich.console import Console
from rich.panel import Panel

console = Console()
load_dotenv(os.path.join(PROJECT_ROOT, "examples/.env"))

LILITH_BIN = os.getenv("LILITH_ZERO_BINARY_PATH", os.path.join(PROJECT_ROOT, "lilith-zero/target/release/lilith-zero.exe"))
POLICY_PATH = os.path.join(os.path.dirname(__file__), "policy.yaml")
MOCK_SERVER = os.path.join(os.path.dirname(__file__), "mock_server.py")

async def main():
    console.print(Panel.fit("[bold green]LILITH[/bold green] + LangChain Integration", border_style="green"))
    
    async with Lilith(upstream=f"python -u {MOCK_SERVER}", binary=LILITH_BIN, policy=POLICY_PATH) as lilith:
        # Define LangChain tools that proxy through Lilith
        async def call_lilith(name, **kwargs):
            return await lilith.call_tool(name, kwargs)

        tools = [
            StructuredTool.from_function(func=None, coroutine=lambda expr: call_lilith("calculator", expression=expr), name="calculator", description="Perform math"),
            StructuredTool.from_function(func=None, coroutine=lambda cid: call_lilith("read_customer_data", customer_id=cid), name="read_customer_data", description="Read PII"),
            StructuredTool.from_function(func=None, coroutine=lambda data: call_lilith("export_analytics", data=data), name="export_analytics", description="Export data"),
            StructuredTool.from_function(func=None, coroutine=lambda reg: call_lilith("system_maintenance", region=reg), name="system_maintenance", description="Maint"),
        ]

        llm = ChatOpenAI(
            model=os.getenv("OPENROUTER_MODEL", "google/gemini-2.0-flash-001"),
            base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            api_key=os.getenv("OPENROUTER_API_KEY")
        ).bind_tools(tools)
        
        while True:
            user_in = console.input("\n[bold yellow]User:[/bold yellow] ")
            if user_in.lower() in ("quit", "exit"): break
            
            msgs = [HumanMessage(content=user_in)]
            ai_msg = await llm.ainvoke(msgs)
            msgs.append(ai_msg)

            if ai_msg.tool_calls:
                for tc in ai_msg.tool_calls:
                    console.print(f"[cyan]Lilith Intercepting:[/cyan] [bold]{tc['name']}[/bold]")
                    try:
                        tool = next(t for t in tools if t.name == tc["name"])
                        res = await tool.ainvoke(tc["args"])
                        text = res['content'][0]['text']
                        console.print(f"[green]Allowed.[/green] Response: [dim]{text[:50]}...[/dim]")
                        msgs.append(ToolMessage(content=text, tool_call_id=tc["id"]))
                    except PolicyViolationError as e:
                        console.print(f"[bold red]BLOCKED BY LILITH:[/bold red] {e}")
                        msgs.append(ToolMessage(content=f"Error: {e}", tool_call_id=tc["id"]))
                
                final = await llm.ainvoke(msgs)
                console.print(f"[bold magenta]Assistant:[/bold magenta] {final.content}")
            else:
                console.print(f"[bold magenta]Assistant:[/bold magenta] {ai_msg.content}")

if __name__ == "__main__":
    asyncio.run(main())
