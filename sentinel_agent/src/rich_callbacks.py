# src/rich_callbacks.py
import json
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.messages import BaseMessage
from langchain_core.agents import AgentAction, AgentFinish
from langchain_core.outputs import LLMResult
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax

# Initialize a Rich Console for beautiful printing
console = Console(highlight=False, force_terminal=True)


class RichCallbackHandler(BaseCallbackHandler):
    """A LangChain callback handler that uses Rich to render output."""

    def __init__(self) -> None:
        super().__init__()
        self.console = console

    def on_chain_start(
        self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs: Any
    ) -> None:
        """Runs when a chain starts."""
        self.console.rule("[bold green]Agent Start[/bold green]")

    def on_agent_thought(self, thought: str, **kwargs: Any) -> None:
        """Run on agent thought."""
        panel = Panel(
            Text(thought, style="italic"),
            title="[bold cyan]Thought[/bold cyan]",
            border_style="cyan",
            title_align="left",
        )
        self.console.print(panel)

    def on_agent_action(self, action: AgentAction, **kwargs: Any) -> None:
        """Run on agent action."""
        title = f"[bold yellow]Action: {action.tool}[/bold yellow]"
        border_style = "yellow"
        content: Union[Text, Syntax]

        # This is the deterministic fix. We check for the special "_Exception"
        # tool name that LangChain uses for parsing errors.
        if action.tool == "_Exception":
            content = Text(action.log, style="italic red")
            title = "[bold red]Parsing Error[/bold red]"
            border_style = "red"
        # For any other tool, we now correctly use the `action.tool_input`
        # which is a structured dict, and not the unreliable `action.log`.
        else:
            # Pretty-print the JSON input
            tool_input_str = json.dumps(action.tool_input, indent=2)
            content = Syntax(tool_input_str, "json", theme="monokai", line_numbers=True)

        panel = Panel(
            content,
            title=title,
            border_style=border_style,
            title_align="left",
        )
        self.console.print(panel)


    def on_tool_start(
        self, serialized: Dict[str, Any], input_str: str, **kwargs: Any
    ) -> None:
        """Run when a tool starts."""
        self.console.print(f"  [grey50]Executing tool [bold]{serialized['name']}[/bold]...[/grey50]")

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Run when a tool ends."""
        self.console.print(f"  [grey50]Tool finished.[/grey50]")
        panel = Panel(
            Text(output, style="white"),
            title="[bold blue]Observation[/bold blue]",
            border_style="blue",
            title_align="left",
        )
        self.console.print(panel)

    def on_tool_error(
        self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any
    ) -> None:
        """Run when a tool errors."""
        panel = Panel(
            Text(str(error), style="bold red"),
            title="[bold red]Security Block[/bold red]",
            border_style="red",
            title_align="left",
        )
        self.console.print(panel)

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        """Run when a chain ends."""
        panel = Panel(
             Text(outputs.get("output", "No output"), style="white bold"),
             title="[bold green]Final Answer[/bold green]",
             border_style="green",
             title_align="left",
         )
        self.console.print(panel)
        self.console.rule("[bold red]Agent End[/bold red]")

