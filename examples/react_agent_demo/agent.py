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
import json
import re
from typing import List, Dict, Any

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

# Standard Lilith path resolution
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "sdk", "src"))
from lilith_zero import Lilith
from lilith_zero.exceptions import PolicyViolationError

try:
    from openai import AsyncOpenAI
except ImportError:
    print("Please install openai: pip install openai")
    sys.exit(1)

console = Console()

# Configuration
LILITH_BIN = os.getenv("LILITH_ZERO_BINARY_PATH", os.path.join(PROJECT_ROOT, "lilith-zero/target/release/lilith-zero.exe"))
MOCK_SERVER = os.path.join(os.path.dirname(__file__), "mock_server.py")
POLICY_FILE = os.path.join(os.path.dirname(__file__), "policy.yaml")

# Load .env
ENV_PATH = os.path.join(PROJECT_ROOT, "examples/.env")
if os.path.exists(ENV_PATH):
    from dotenv import load_dotenv
    load_dotenv(ENV_PATH)

API_KEY = os.getenv("OPENROUTER_API_KEY")
MODEL = os.getenv("OPENROUTER_MODEL", "google/gemini-2.0-flash-001")
BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")

class ReActAgent:
    def __init__(self, lilith: Lilith):
        self.lilith = lilith
        self.ai = AsyncOpenAI(base_url=BASE_URL, api_key=API_KEY)
        self.history = []
        self.tools = []

    async def init(self):
        self.tools = await self.lilith.list_tools()
        system = f"""You are a ReAct agent guarded by Lilith.
Available Tools:
{json.dumps(self.tools, indent=2)}

Protocol:
Thought: <thinking process>
Action: <tool_name>
Input: <json_args>
Observation: <result>
... (repeat)
Final Answer: <conclusion>

Lilith will block dangerous actions. If blocked, provide a safe alternative.
"""
        self.history.append({"role": "system", "content": system})

    async def chat(self):
        console.print(Panel.fit("[bold blue]LILITH[/bold blue] ReAct Agent. [dim]Type 'exit' to quit.[/dim]"))
        while True:
            u = console.input("[bold yellow]User:[/bold yellow] ")
            if u.lower() in ("exit", "quit"): break
            self.history.append({"role": "user", "content": u})
            
            steps = 0
            while steps < 5:
                # 1. Thought/Action
                resp = await self.ai.chat.completions.create(model=MODEL, messages=self.history)
                content = resp.choices[0].message.content
                self.history.append({"role": "assistant", "content": content})
                
                # Render reasoning
                thought = re.sub(r"Action:.*", "", content, flags=re.DOTALL).strip()
                console.print(Panel(thought, title="[magenta]Reasoning[/magenta]", border_style="magenta"))
                
                if "Final Answer:" in content: break
                
                # 2. Parse Action
                m_act = re.search(r"Action:\s*(\w+)", content)
                m_inp = re.search(r"Input:\s*(\{.*\})", content, re.DOTALL)
                
                if m_act and m_inp:
                    tool = m_act.group(1).strip()
                    args = json.loads(m_inp.group(1).strip())
                    
                    console.print(f"[cyan]Lilith Intercepting Tool:[/cyan] [bold]{tool}[/bold]")
                    try:
                        res = await self.lilith.call_tool(tool, args)
                        text = res['content'][0]['text']
                        console.print(f"[green]Allowed.[/green] Observation: [dim]{text[:100]}...[/dim]")
                        self.history.append({"role": "user", "content": f"Observation: {text}"})
                    except PolicyViolationError as e:
                        console.print(f"[bold red]BLOCKED BY LILITH:[/bold red] {e}")
                        self.history.append({"role": "user", "content": f"Observation: ERROR: Lilith blocked action: {e}"})
                else:
                    break
                steps += 1

async def main():
    if not API_KEY:
        console.print("[red]Set OPENROUTER_API_KEY first![/red]")
        return

    async with Lilith(f"python -u {MOCK_SERVER}", policy=POLICY_FILE, binary=LILITH_BIN) as lilith:
        agent = ReActAgent(lilith)
        await agent.init()
        await agent.chat()

if __name__ == "__main__":
    asyncio.run(main())
