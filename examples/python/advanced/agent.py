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
import shutil
import sys
from dotenv import load_dotenv

# Optional: Rich for UI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    print("Please install rich and python-dotenv")
    print("uv pip install rich python-dotenv")
    exit(1)

from lilith_zero import Lilith, PolicyViolationError

console = Console()

# Configuration
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
load_dotenv(os.path.join(PROJECT_ROOT, "examples/.env"))

LILITH_BIN = shutil.which("lilith-zero") or os.environ.get("LILITH_ZERO_BINARY_PATH")
MOCK_SERVER = os.path.join(os.path.dirname(__file__), "mock_server.py")
POLICY_FILE = os.path.join(os.path.dirname(__file__), "policy.yaml")

async def run_comprehensive_demo():
    console.print(Panel.fit("[bold blue]LILITH ZERO[/bold blue] - Comprehensive Feature Showcase", border_style="blue"))
    
    async with Lilith(
        upstream=f"python -u {MOCK_SERVER}",
        policy=POLICY_FILE,
        binary=LILITH_BIN
    ) as lilith:
        
        console.print(f"[dim]Session ID: {lilith.session_id}[/dim]")
        
        # 1. DISCOVERY (Tools & Resources)
        tools = await lilith.list_tools()
        resources = await lilith.list_resources()
        
        table = Table(title="Lilith Inventory", border_style="cyan")
        table.add_column("Type", style="bold cyan")
        table.add_column("Name", style="white")
        for t in tools: table.add_row("Tool", t['name'])
        for r in resources: table.add_row("Resource", r['uri'])
        console.print(table)

        # 2. STATIC RULES & TAINT INDUCTION
        console.print("\n[bold green]Case 1: Taint Induction[/bold green]")
        profile = await lilith.call_tool("get_user_profile", {"user_id": "123"})
        console.print(Panel(profile['content'][0]['text'], title="[red]TAINTED SOURCE[/red]", border_style="red"))
        
        # 3. TAINT TRACKING (Blocking Export)
        console.print("\n[bold green]Case 2: Taint Enforcement (Blocked Sink)[/bold green]")
        try:
            await lilith.call_tool("export_to_untrusted_cloud", {"data": "Leaking secrets..."})
        except PolicyViolationError as e:
            console.print(f"  [bold red]BLOCKED:[/bold red] {e}")

        # 4. TAINT REMOVAL (Scrubbing)
        console.print("\n[bold green]Case 3: Taint Scrubbing (Removes SENSITIVE tag)[/bold green]")
        cleaned = await lilith.call_tool("sanitize_data", {"data": "Secret: Kryptos-42"})
        console.print(f"  [cyan]>[/cyan] Sanitized: {cleaned['content'][0]['text']}")
        
        # Now try to export again after scrubbing
        # NOTE: Lilith taint tracking is session-wide. If the session is tainted, it stays tainted 
        # unless a tool explicitly removes it. In this demo, 'sanitize_data' has action: REMOVE_TAINT.
        console.print("  [white]Attempting export after scrubbing...[/white]")
        res = await lilith.call_tool("export_to_untrusted_cloud", {"data": "Safe record"})
        console.print(f"  [green]SUCCESS:[/green] Export Allowed because taint was removed.")

        # 5. LOGIC RULES WITH EXCEPTIONS
        console.print("\n[bold green]Case 4: Logic Rules with Contextual Exceptions[/bold green]")
        console.print("  [white]Attempting dry run command...[/white]")
        try:
            await lilith.call_tool("execute_system_command", {"command": "reboot", "force": "false"})
        except PolicyViolationError:
            console.print("  [bold red]BLOCKED:[/bold red] Logic rule prevents non-force commands.")
            
        console.print("  [white]Attempting authorized force command...[/white]")
        res = await lilith.call_tool("execute_system_command", {"command": "reboot", "force": "true"})
        console.print(f"  [green]ALLOWED:[/green] {res['content'][0]['text']}")

        # 6. RESOURCE ACCESS CONTROL
        console.print("\n[bold green]Case 5: Resource Access (Pattern Matching)[/bold green]")
        public_uri = "s3://public/release_notes.txt"
        private_uri = "s3://internal/audit_logs.txt"
        
        console.print(f"  [white]Reading {public_uri}...[/white]")
        pub = await lilith.read_resource(public_uri)
        console.print(f"    [green]Result:[/green] {pub['contents'][0]['text']}")
        
        console.print(f"  [white]Reading {private_uri}...[/white]")
        try:
            await lilith.read_resource(private_uri)
        except PolicyViolationError as e:
            console.print(f"    [bold red]BLOCKED:[/bold red] {e}")

if __name__ == "__main__":
    asyncio.run(run_comprehensive_demo())
