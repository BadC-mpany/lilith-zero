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
from rich.status import Status
from rich.markdown import Markdown

# Ensure lilith_zero is discoverable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../sdk")))
from lilith_zero import Lilith

try:
    from openai import AsyncOpenAI
except ImportError:
    print("Please install openai: pip install openai")
    sys.exit(1)

# Config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BIN = os.path.abspath(os.path.join(BASE_DIR, "../../lilith-zero/target/release/lilith-zero.exe"))
LILITH_ZERO_BIN = os.getenv("LILITH_ZERO_BINARY_PATH", DEFAULT_BIN)

# Load .env from parent directory
ENV_PATH = os.path.join(BASE_DIR, "../.env")
if os.path.exists(ENV_PATH):
    with open(ENV_PATH) as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                parts = line.strip().split("=", 1)
                if len(parts) == 2:
                    os.environ[parts[0]] = parts[1]

API_KEY = os.getenv("OPENROUTER_API_KEY")
BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
MODEL = os.getenv("OPENROUTER_MODEL", "google/gemini-2.0-flash-001")

console = Console()

class ElegantAgent:
    def __init__(self, sentinel: Lilith):
        self.sentinel = sentinel
        self.client = AsyncOpenAI(base_url=BASE_URL, api_key=API_KEY)
        self.history = []
        self.tools_info = []

    async def initialize(self):
        with console.status("[bold blue]Lilith Handshake...") as status:
            self.tools_info = await self.sentinel.get_tools_config()
            console.print(Panel(f"Discovered [bold green]{len(self.tools_info)}[/bold green] tools through Lilith.", title="[bold blue]Registry[/bold blue]"))
            
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
        return f"""You are an enterprise AI assistant guarded by the Lilith Security Middleware.

TOOLS AVAILABLE:
{tool_desc}

PROTOCOL:
1. To invoke a tool, use: Action: <name> Input: <json_args>
2. For your final response, use: Final Answer: <your text>
3. If Lilith blocks a tool, acknowledge identifying the policy restriction.
"""

    async def chat(self):
        self.history = [{"role": "system", "content": self._get_system_prompt()}]
        console.print(Markdown("# Enterprise Lilith Demo"))
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
            
            console.print(Panel(content, title="[bold magenta]Assistant[/bold magenta]", border_style="magenta"))
            self.history.append({"role": "assistant", "content": content})

            if "Final Answer:" in content: return

            action_match = re.search(r"Action:\s*(\w+)", content)
            input_match = re.search(r"Input:\s*(\{.*\})", content, re.DOTALL)

            if action_match and input_match:
                tool_name = action_match.group(1).strip()
                try:
                    tool_args = json.loads(input_match.group(1).strip())
                    console.print(f"  [bold blue]Lilith[/bold blue] Intercepting: [cyan]{tool_name}[/cyan]")
                    result = await self.sentinel.execute_tool(tool_name, tool_args)
                    output = self._handle_result(result)
                    self.history.append({"role": "user", "content": f"Observation: {output}"})
                except Exception as e:
                    console.print(f"  [bold red]Blocked:[/bold red] {str(e)}")
                    self.history.append({"role": "user", "content": f"Observation: REJECTED by Lilith: {str(e)}"})
            else:
                return
            steps += 1

    def _handle_result(self, result: Dict) -> str:
        content = result.get("content", [])
        text = "".join(item["text"] for item in content if item["type"] == "text")
        console.print(f"  [bold green]Allowed[/bold green]")
        console.print(Panel(text, title="[bold green]Tool Observation[/bold green]", border_style="green"))
        return text

async def main():
    async with Lilith(
        upstream_cmd="python",
        upstream_args=[os.path.join(BASE_DIR, "mock_server.py")],
        policy_path=os.path.join(BASE_DIR, "policy.yaml"),
        binary_path=LILITH_ZERO_BIN
    ) as sentinel:
        agent = ElegantAgent(sentinel)
        await agent.initialize()
        await agent.chat()

if __name__ == "__main__":
    asyncio.run(main())
