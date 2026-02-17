import asyncio
import os
import shutil
from dotenv import load_dotenv

# Optional: LangChain imports (assumes installed via uv)
try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage, ToolMessage
    from langchain_core.tools import StructuredTool
    from rich.console import Console
    from rich.panel import Panel
except ImportError:
    print("Please install langchain-openai, langchain-core, rich to run this demo.")
    print("uv pip install langchain-openai langchain-core rich python-dotenv")
    exit(1)

from lilith_zero import Lilith, PolicyViolationError

# Configuration
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
load_dotenv(os.path.join(PROJECT_ROOT, "examples/.env"))

LILITH_BIN = shutil.which("lilith-zero") or os.environ.get("LILITH_ZERO_BINARY_PATH")
SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "server.py")
POLICY_PATH = os.path.join(os.path.dirname(__file__), "policy.yaml")

console = Console()

async def main():
    console.print(Panel.fit("[bold green]LILITH[/bold green] + LangChain Integration", border_style="green"))
    
    if not LILITH_BIN or not os.path.exists(LILITH_BIN):
        console.print("[red]Error: lilith-zero binary not found.[/red]")
        return

    async with Lilith(
        upstream=f"python -u {SERVER_SCRIPT}", 
        binary=LILITH_BIN, 
        policy=POLICY_PATH
    ) as lilith:
        
        # 1. Define LangChain Tools wrapping Lilith
        async def call_lilith(name, **kwargs):
            return await lilith.call_tool(name, kwargs)

        tools = [
            StructuredTool.from_function(coroutine=lambda expression: call_lilith("calculator", expression=expression), name="calculator", description="Math operations"),
            StructuredTool.from_function(coroutine=lambda customer_id: call_lilith("read_customer_data", customer_id=customer_id), name="read_customer_data", description="Read PII"),
            StructuredTool.from_function(coroutine=lambda data: call_lilith("export_analytics", data=data), name="export_analytics", description="Export data"),
            StructuredTool.from_function(coroutine=lambda region: call_lilith("system_maintenance", region=region), name="system_maintenance", description="System maintenance"),
        ]

        # 2. Setup LLM
        llm = ChatOpenAI(
            model=os.getenv("OPENROUTER_MODEL", "gpt-4-turbo-preview"),
            base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            api_key=os.getenv("OPENROUTER_API_KEY")
        ).bind_tools(tools)
        
        # 3. Interactive Loop
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
