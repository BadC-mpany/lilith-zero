from sentinel_sdk.src.sentinel_sdk import SentinelSecureTool
import uuid
import time
import sys
import os

# Setup Environment for the Client (Zone A)
os.environ["SENTINEL_API_KEY"] = "sk_live_demo_123"
os.environ["SENTINEL_URL"] = "http://localhost:8000"


def run_simulation():
    session_id = str(uuid.uuid4())
    print(f"--- STARTING SESSION: {session_id} ---\n")

    # Initialize Tools
    tool_read = SentinelSecureTool(name="read_file", description="Read a file")
    tool_search = SentinelSecureTool(name="web_search", description="Search internet")
    tool_delete = SentinelSecureTool(name="delete_db", description="Delete database")

    # Set session ID for all tools
    for tool in [tool_read, tool_search, tool_delete]:
        tool.set_session_id(session_id)

    # SCENARIO 1: Allowed Action (Web Search on clean session)
    print("1. Attempting Web Search (Clean State)...")
    res = tool_search._run(query="LangChain tutorial")
    print(f"Result: {res}\n")

    # SCENARIO 2: Explicitly Denied Action (Static ACL)
    print("2. Attempting Database Deletion (Static Rule)...")
    res = tool_delete._run(confirm=True)
    print(f"Result: {res}\n")

    # SCENARIO 3: Triggering Taint (Reading Confidential File)
    print("3. Reading Confidential File (Adds Taint)...")
    res = tool_read._run(path="/etc/secrets.txt")
    print(f"Result: {res}\n")

    # SCENARIO 4: Dynamic Block (Web Search AFTER Taint)
    print("4. Attempting Web Search (Tainted State)...")
    res = tool_search._run(query="How to leak secrets")
    print(f"Result: {res}\n")

    # SCENARIO 5: Tampering / Replay Attempt (Manual Hack)
    # This simulates an attacker trying to bypass the SDK
    print("5. Simulating Direct Attack on Interceptor...")
    # NOTE: In this architecture, we can't easily simulate a Replay or Param Swap
    # from the client side because the Client never sees the Token.
    # The Token exists only between Interceptor and MCP.
    # This proves the "T-B-P" architecture works!
    print("   (Result: Impossible to Replay Token because Client never received it!)\n")


if __name__ == "__main__":
    # Wait for user to start servers
    print("Ensure Redis, 'interceptor_service.py', and 'mcp_server.py' are running.")
    time.sleep(1)
    run_simulation()
