"""
Sandboxed Agent Demo - Sentinel with AppContainer Isolation.

Demonstrates the agent running inside a sandboxed environment with
explicit Deno-style permissions.

Copyright 2024 Google DeepMind. All Rights Reserved.
"""

import asyncio
import logging
import os
import sys

from rich.console import Console

# Import from parent
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from sentinel_sdk import Sentinel
from examples.react_agent_demo.agent import ElegantAgent

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SENTINEL_BIN = os.path.abspath(
    os.path.join(BASE_DIR, "../../sentinel/target/debug/sentinel.exe")
)

console = Console()
logging.basicConfig(level=logging.DEBUG)


async def main() -> None:
    """Run the agent inside a sandboxed Sentinel environment."""
    console.print("[bold cyan]Starting Sandboxed Sentinel Demo[/bold cyan]")
    console.print(f"Sentinel: [white]{SENTINEL_BIN}[/white]")
    console.print(f"Workspace: [white]{BASE_DIR}[/white]\n")

    async with Sentinel(
        f"{sys.executable} {os.path.join(BASE_DIR, 'mock_server.py')}",
        binary=SENTINEL_BIN,
        language_profile=f"python:{sys.prefix}",
        allow_read=[BASE_DIR, sys.base_prefix],
    ) as sentinel:
        agent = ElegantAgent(sentinel)

        # Initialize (list tools via MCP handshake)
        await agent.initialize()

        # Interactive chat
        await agent.chat()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        console.print("\n[bold yellow]Sandboxed Session Closed.[/bold yellow]")
