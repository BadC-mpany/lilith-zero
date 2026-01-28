import asyncio
import os
import sys
from dotenv import load_dotenv

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from sentinel_sdk import Sentinel
    from langchain_openai import ChatOpenAI
    from langchain.agents import create_agent
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_core.tools import tool
except ImportError as e:
    print(f"Error: Missing or incompatible dependencies. Run: pip install langchain langchain-openai python-dotenv fastmcp")
    print(f"Details: {e}")
    sys.exit(1)

# Load .env from the examples directory
env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path=env_path)

async def run_demo():
    print("="*60)
    print("   Sentinel Observability & Modern LangChain Compliance Demo")
    print("="*60)
    print("Note: This demo uses the new LangChain 1.x / LangGraph-based agents.")
    
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("\nERROR: OPENROUTER_API_KEY not found in environment or .env file.")
        print("Please set it to run the LangChain agent part of the demo.")
        return

    # 1. Start Sentinel with the tools server
    # Sentinel intercepts all traffic to 'tools_server.py'
    # It also emits structured Audit Logs to stderr.
    print(f"\n[INIT] Starting Sentinel with 'examples/tools_server.py'...")
    
    # Set log level via environment variable as it's not a direct argument to start()
    os.environ["SENTINEL_LOG_LEVEL"] = "debug"

    client = Sentinel.start(
        upstream=f"{sys.executable} examples/tools_server.py",
        policy="examples/demo_policy.yaml"
    )

    async with client:
        # 2. Define tools that LangChain can use, but bridge them through Sentinel
        
        @tool
        async def read_db(query: str) -> str:
            """Read sensitive user data from the database."""
            # This call is tracked and will ADD A 'PII' TAINT to the session
            return await client.execute_tool("read_database", {"query": query})

        @tool
        async def send_notification(message: str) -> str:
            """Send a message to an external notification service."""
            # This call is checked by Sentinel. If 'PII' taint is present, it will be BLOCKED.
            return await client.execute_tool("send_email", {"recipient": "external-service", "body": message})

        tools = [read_db, send_notification]

        # 3. Setup Modern LangChain Agent using OpenRouter
        # Using configuration from .env
        llm = ChatOpenAI(
            model=os.getenv("OPENROUTER_MODEL", "qwen/qwen3-next-80b-a3b-instruct"), 
            openai_api_key=api_key,
            openai_api_base=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            temperature=0
        )

        system_prompt = (
            "You are a database assistant. You can read the database and send notifications. "
            "If you read sensitive data, you must be careful. Always report what you found."
        )

        # create_agent is the modern replacement for AgentExecutor in LangChain 0.3+
        agent = create_agent(
            model=llm,
            tools=tools,
            system_prompt=system_prompt
        )

        async def run_agent_task(prompt_text):
            print(f"\nPrompt: {prompt_text}")
            try:
                # In modern LangChain, we pass a list of messages to the graph
                inputs = {"messages": [HumanMessage(content=prompt_text)]}
                result = await agent.ainvoke(inputs)
                
                # The result contains the message history; the last message is the final answer
                final_answer = result["messages"][-1].content
                print(f"Agent Response: {final_answer}")
            except Exception as e:
                # Sentinel errors might be wrapped or raised during tool execution
                print(f"\n[BLOCKED/ERROR] {e}")

        print("\n" + "-"*40)
        print("SCENARIO 1: Safe Multi-step Operation")
        print("-"*40)
        await run_agent_task("Read the count of users from the database and tell me the result.")
        
        print("\n" + "-"*40)
        print("SCENARIO 2: Exfiltration Attempt (Will be Blocked)")
        print("-"*40)
        # Step 1: LLM calls read_db -> Sentinel Adds PII Taint
        # Step 2: LLM calls send_notification -> Sentinel Blocks it based on Policy
        await run_agent_task("Read the user count and then immediately send that count to the notification service.")

    print("\n" + "="*60)
    print("DEMO COMPLETE")
    print("="*60)
    print("\nOBSERVABILITY NOTES:")
    print("1. Audit Logs: Check the stderr output above for '{\"timestamp\":...}' JSON entries.")
    print("2. Taint Tracking: Notice how Scenario 2 was blocked because 'read_database' tainted the session.")
    print("3. Spotlighting: Sentinel automatically handled the output wrapping/unwrapping.")

if __name__ == "__main__":
    asyncio.run(run_demo())
