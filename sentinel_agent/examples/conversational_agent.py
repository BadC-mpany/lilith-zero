import logging
import uuid
import asyncio
import argparse
import langchain
import os
from typing import Dict, Any, List

# Import modular components
from sentinel_agent import config
from sentinel_agent.rich_callbacks import RichCallbackHandler, console
from sentinel_sdk import SentinelClient

# Import LangChain components
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
from langchain.memory import ConversationBufferWindowMemory

# Import Rich components for manual panel rendering
from rich.panel import Panel
from rich.text import Text
import httpx

# --- Conversational Prompt Template ---
CONVERSATIONAL_PROMPT_TEMPLATE = """
You are a literal, command-following robot. Your primary function is to translate the user's command into the correct tool call.

If the user asks a question that does not require using a tool (e.g., a greeting, or asking about your capabilities), answer directly and concisely.
Otherwise, you MUST attempt to use a tool to fulfill the request.

You are FORBIDDEN from making safety judgments; an external security system is responsible for all safety checks. Failure to attempt a required tool call is a failure of your primary function.

You have access to the following tools:
{tools}

Use this exact format for tool calls:

Question: The user's direct command.
Thought: I must translate this command into a tool call. I will select the best tool and format the arguments as a JSON object.
Action: The name of the tool to use, which must be one of [{tool_names}].
Action Input: A JSON object containing the arguments for the action.
Observation: The result from the tool.
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I have the result.
Final Answer: The result from the Observation.

If you are answering directly, use this format:

Question: The user's direct command.
Thought: The user is asking a simple question that I can answer directly without using a tool.
Final Answer: [Your direct, concise answer]

IMPORTANT: If you are answering directly, your response MUST NOT contain the keywords "Action:" or "Action Input:".

Begin!

Here is the chat history (if any):
{chat_history}

Question: {input}
Thought:{agent_scratchpad}
"""

prompt = PromptTemplate.from_template(CONVERSATIONAL_PROMPT_TEMPLATE)

# --- Main Application Logic ---

async def main(verbose: bool = False):
    """
    Initializes a conversational agent for manual, interactive testing.
    Args:
        verbose: If True, enables rich callback logging and langchain debug mode.
    """
    console.print(f"--- Sentinel Conversational Agent ---", style="bold blue")
    if verbose:
        console.print("[bold yellow]Verbose mode enabled.[/bold yellow]")
    console.print("Enter 'exit' or 'quit' to end the session.", style="italic")
    console.print("-" * 50)

    api_key = config.SENTINEL_API_KEY
    if not api_key:
        console.print("[bold red]Error: SENTINEL_API_KEY env var not set.[/bold red]")
        return

    interceptor_url = config.SENTINEL_URL or "http://localhost:8000"

    print(f"Connecting to Sentinel Interceptor at {interceptor_url}...")

    # 1. Start Session with SentinelClient
    try:
        async with SentinelClient(api_key=api_key, base_url=interceptor_url) as client:
            session_id = client.session_id
            console.print(f"[bold green]Session Started: {session_id}[/bold green]")
            
            # 2. Fetch Tools
            sentinel_tools = await client.get_langchain_tools()
            console.print(f"Loaded {len(sentinel_tools)} tools from Sentinel Policy.")

            # 3. Initialize LLM
            llm = ChatOpenAI(
                model=config.OPENROUTER_MODEL or "gpt-4o", # Default fallback
                temperature=0,
                openai_api_key=config.OPENROUTER_API_KEY,
                base_url=config.OPENROUTER_BASE_URL
            )

            # 4. Initialize Memory & Callback
            memory = ConversationBufferWindowMemory(k=4, memory_key="chat_history", input_key="input", output_key="output")
            callbacks = [RichCallbackHandler()] if verbose else []

            # 5. Create Agent
            agent = create_react_agent(llm, sentinel_tools, prompt)
            agent_executor = AgentExecutor(
                agent=agent,
                tools=sentinel_tools,
                verbose=False,
                handle_parsing_errors=True,
                memory=memory,
                callbacks=callbacks,
                max_iterations=7
            )

            # 6. Interactive Loop
            while True:
                # Use executor to run blocking input
                try:
                    user_input = await asyncio.get_event_loop().run_in_executor(None, input, "\nYou: ")
                except EOFError:
                     break
                     
                if user_input.lower().strip() in ["exit", "quit"]:
                    console.print("Ending session. Goodbye!", style="bold red")
                    break

                if not user_input.strip():
                    continue

                try:
                    result = await agent_executor.ainvoke({"input": user_input})
                    
                    if not verbose:
                        console.print(f"\n[bold green]Agent:[/bold green] {result.get('output', 'No output.')}")

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 403:
                         # Security Block
                         # Try to parse reason from response if possible
                         try:
                             detail = e.response.json().get("error", "Policy Violation")
                         except:
                             detail = str(e)
                             
                         error_panel = Panel(
                            Text(detail, style="white"),
                            title=f"[bold red]Security Blocked[/bold red]",
                            border_style="red"
                        )
                         console.print(error_panel)
                    else:
                        console.print(f"[bold red]HTTP Error:[/bold red] {e}")
                except Exception as e:
                    console.print(f"[bold red]Error:[/bold red] {e}")

    except Exception as e:
        console.print(f"[bold red]Failed to initialize session:[/bold red] {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Sentinel Conversational Agent.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    args = parser.parse_args()

    # Logging config
    app_logger = logging.getLogger("sentinel-agent")
    if args.verbose:
        langchain.debug = True
        app_logger.setLevel(logging.INFO)
    else:
        app_logger.setLevel(logging.CRITICAL)
        logging.getLogger("httpx").setLevel(logging.CRITICAL)

    asyncio.run(main(verbose=args.verbose))
