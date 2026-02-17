import asyncio
import os
import shutil
import sys
from lilith_zero import Lilith, PolicyViolationError

# Configuration
LILITH_BIN = shutil.which("lilith-zero") or os.environ.get("LILITH_ZERO_BINARY_PATH")
# We assume the user runs this with 'uv run', so 'server.py' is in the same dir
SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "server.py")
POLICY_FILE = os.path.join(os.path.dirname(__file__), "policy.yaml")

async def main():
    print("--- Lilith + FastMCP Demo ---")
    
    if not LILITH_BIN or not os.path.exists(LILITH_BIN):
        print("Error: lilith-zero binary not found.")
        return

    # Wrap the FastMCP server with Lilith
    # FastMCP servers run with 'python server.py' default to stdio
    async with Lilith(
        upstream=f"python -u {SERVER_SCRIPT}",
        policy=POLICY_FILE,
        binary=LILITH_BIN
    ) as lilith:
        
        print(f"Session Active: {lilith.session_id[:8]}...")
        
        # 1. List Tools
        tools = await lilith.list_tools()
        print(f"Tools: {[t['name'] for t in tools]}")

        # 2. Call Tool (Allowed)
        print("\n> Calling 'add(10, 20)'...")
        res = await lilith.call_tool("add", {"a": 10, "b": 20})
        print(f"Result: {res['content'][0]['text']}")

        # 3. Call Resource (Allowed)
        print("\n> Reading 'greetings://Alice'...")
        res = await lilith.read_resource("greetings://Alice")
        print(f"Result: {res['contents'][0]['text']}")

if __name__ == "__main__":
    asyncio.run(main())
