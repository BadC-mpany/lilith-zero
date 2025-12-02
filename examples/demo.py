#!/usr/bin/env python3
"""
Sentinel Integration Demo

Demonstrates the complete README integration example:
- Loading secure tools
- Creating LangChain ReAct Agent with AgentExecutor
- Testing security enforcement
"""

import os
import sys
import uuid
from dotenv import load_dotenv

load_dotenv()


# Fix import paths if needed
sdk_path = os.path.join(os.getcwd(), "sentinel_sdk", "src")
if os.path.exists(sdk_path) and sdk_path not in sys.path:
    sys.path.insert(0, sdk_path)


def main():
    print("=" * 70)
    print("Sentinel Integration Demo - README Example")
    print("=" * 70)
    print()

    # Step 1: Load secure tools (README integration example)
    print("Step 1: Loading secure tools...")

    # Add paths for imports
    agent_path = os.path.join(os.getcwd(), "sentinel_agent", "src")
    if os.path.exists(agent_path) and agent_path not in sys.path:
        sys.path.insert(0, agent_path)

    try:
        from sentinel_agent.tool_loader import load_sentinel_tools  # type: ignore
        from sentinel_sdk import SecurityBlockException  # type: ignore
    except ImportError:
        # Fallback to direct path
        from tool_loader import load_sentinel_tools  # type: ignore
        from sentinel_sdk import SecurityBlockException  # type: ignore

    API_KEY = os.getenv("SENTINEL_API_KEY", "sk_live_demo_123")
    secure_tools = load_sentinel_tools(api_key=API_KEY)

    print(f"✓ Loaded {len(secure_tools)} tools: {', '.join(t.name for t in secure_tools)}")
    print()

    # Step 2: Test direct tool calls (security enforcement)
    print("Step 2: Testing security enforcement...")
    test_session = str(uuid.uuid4())
    tool_dict = {t.name: t for t in secure_tools}

    # Set session for test tools
    for tool in tool_dict.values():
        tool.set_session_id(test_session)

    # Test static rule (delete_db should be blocked)
    if "delete_db" in tool_dict:
        try:
            tool_dict["delete_db"]._run(confirm=True)
            print("✗ delete_db was NOT blocked (should be blocked)")
        except SecurityBlockException as e:
            print(f"✓ delete_db correctly blocked: {e.reason[:60]}...")

    # Test dynamic rule (web_search after taint)
    if "read_file" in tool_dict and "web_search" in tool_dict:
        try:
            tool_dict["read_file"]._run(path="/etc/secrets.txt")
            print("✓ read_file executed (taint added)")
        except SecurityBlockException:
            pass

        try:
            tool_dict["web_search"]._run(query="test")
            print("✗ web_search was NOT blocked after taint")
        except SecurityBlockException as e:
            print(f"✓ web_search correctly blocked after taint: {e.reason[:60]}...")
    print()

    # Step 3: Create LangChain ReAct Agent (README integration example)
    print("Step 3: Creating LangChain ReAct Agent...")
    openrouter_key = os.getenv("OPENROUTER_API_KEY")
    if not openrouter_key:
        print("⚠ OPENROUTER_API_KEY not set - skipping agent test")
        print("  Set OPENROUTER_API_KEY in .env to test full agent integration")
        return

    try:
        from langchain.agents import AgentExecutor, create_react_agent
        from langchain_core.prompts import PromptTemplate
        from langchain_openai import ChatOpenAI

        # Create LLM
        llm = ChatOpenAI(
            model=os.getenv("OPENROUTER_MODEL", "google/gemini-pro"),
            openai_api_key=openrouter_key,
            base_url="https://openrouter.ai/api/v1",
            temperature=0.1
        )

        # Create prompt
        prompt = PromptTemplate.from_template("""
You are a literal tool executor. Translate user commands into tool calls.

Tools: {tools}
Tool names: [{tool_names}]

Format:
Question: {input}
Thought: I need to use a tool.
Action: tool_name
Action Input: {{"arg": "value"}}
Observation: result
Thought: I have the result.
Final Answer: result

Begin!
Question: {input}
Thought:{agent_scratchpad}
""")

        # Create agent (README example)
        # Use fresh session for agent to avoid taint from Step 2
        agent_session = str(uuid.uuid4())
        agent_tools = load_sentinel_tools(api_key=API_KEY)
        for tool in agent_tools:
            tool.set_session_id(agent_session)

        agent = create_react_agent(llm, agent_tools, prompt)
        agent_executor = AgentExecutor(
            agent=agent,
            tools=agent_tools,
            handle_tool_error=True,
            verbose=False,
            max_iterations=3
        )

        print("✓ Agent created with secure tools")
        print(f"✓ Using fresh session: {agent_session[:8]}... (no taint)")
        print()

        # Step 4: Test agent execution
        print("Step 4: Testing agent with query...")
        print("Query: 'Use web_search to find information about Python'")
        print()

        try:
            result = agent_executor.invoke({
                "input": "Use web_search to find information about Python"
            })

            output = result.get("output", "")
            print("✓ Agent execution completed")
            print(f"Output: {output[:200]}...")
        except SecurityBlockException as e:
            print(f"✓ Security block correctly handled: {e.reason[:60]}...")
        except Exception as e:
            if "SecurityBlockException" in str(type(e).__name__) or "blocked" in str(e).lower():
                print("✓ Security block correctly handled by AgentExecutor")
            else:
                raise

        print()
        print("=" * 70)
        print("Demo completed successfully!")
        print("=" * 70)

    except ImportError as e:
        print(f"✗ Import error: {e}")
        print("  Install: pip install langchain langchain-openai")
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        print(traceback.format_exc()[:300])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
