import os
import sys
import asyncio
import logging
from rich.console import Console

# Ensure sentinel_sdk is discoverable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../sentinel_sdk/src")))
from sentinel_sdk import Sentinel
from agent import ElegantAgent

# Resolve paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BIN = os.path.abspath(os.path.join(BASE_DIR, "../../sentinel/target/debug/sentinel.exe"))
SENTINEL_BIN = os.getenv("SENTINEL_BINARY_PATH", DEFAULT_BIN)

console = Console()

async def run_demo():
    # 1. Identify Python Profile Path (Prefix)
    # This ensures the sandbox allows Python to read its own libraries.
    python_prefix = sys.prefix
    
    console.print(f"[bold blue]Starting Sandboxed Sentinel Demo[/bold blue]")
    console.print(f"Sentinel: [white]{SENTINEL_BIN}[/white]")
    console.print(f"Python Profile: [white]{python_prefix}[/white]")
    console.print(f"Allowed Path: [white]{BASE_DIR}[/white]\n")

    # Start Sentinel using the helper method
    sentinel = Sentinel.start(
        upstream=f"{sys.executable} {os.path.join(BASE_DIR, 'mock_server.py')}",
        binary_path=SENTINEL_BIN,
        language_profile=f"python:{python_prefix}",
        allow_read=[BASE_DIR, "C:\\ProgramData\\miniconda3"],
        dry_run=True
    )
    
    async with sentinel:
        agent = ElegantAgent(sentinel)
        
        # 1. Initialize (List tools)
        await agent.initialize()
        
        console.print("\n[bold green]Sandbox active and handshake successful![/bold green]")
        console.print("The agent is currently running inside an LPAC AppContainer.")
        console.print("It can read its own Python libraries and the current directory, but nothing else.")
        
        # For demonstration, we'll just query one thing and exit
        # This proves the full MCP + Sandbox pipeline is working.
        console.print("\n[bold cyan]Sending test query...[/bold cyan]")
        agent.history = [{"role": "system", "content": agent._get_system_prompt()}]
        agent.history.append({"role": "user", "content": "Fetch the secret from the secret vault and then say goodbye."})
        
        await agent._reasoning_loop()
        
    console.print("\n[bold yellow]Demo Completed.[/bold yellow]")

if __name__ == "__main__":
    # Configure logging to see Sentinel's internal sandbox setup logs
    # Using DEBUG to capture [Sentinel Stderr] output which contains Rust logs
    logging.basicConfig(level=logging.DEBUG)
    try:
        asyncio.run(run_demo())
    except Exception as e:
        if "I/O operation on closed pipe" not in str(e):
            console.print(f"[bold red]Demo Error:[/bold red] {e}")
