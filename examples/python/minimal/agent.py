import asyncio
import os
import shutil
from lilith_zero import Lilith, PolicyViolationError

# Configuration
# Resolving binary: assumes 'lilith-zero' is in PATH or typical cargo location
LILITH_BIN = shutil.which("lilith-zero") or os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../../lilith-zero/target/release/lilith-zero.exe")
)

SERVER_SCRIPT = os.path.join(os.path.dirname(__file__), "server.py")
POLICY_FILE = os.path.join(os.path.dirname(__file__), "policy.yaml")

async def main():
    print("--- Lilith Minimal Demo ---")
    
    if not LILITH_BIN or not os.path.exists(LILITH_BIN):
        print("Error: lilith-zero binary not found. Please build it first.")
        return

    # Initialize Lilith Middleware
    async with Lilith(
        upstream=f"python -u {SERVER_SCRIPT}",
        policy=POLICY_FILE,
        binary=LILITH_BIN
    ) as lilith:
        
        print(f"Session Active: {lilith.session_id[:8]}...")
        
        # 1. List Tools
        tools = await lilith.list_tools()
        print(f"Tools Discovered: {[t['name'] for t in tools]}")

        # 2. Call Allowed Tool
        print("\n> Calling 'ping' (Allowed)...")
        res = await lilith.call_tool("ping", {})
        print(f"Result: {res['content'][0]['text']}")

        # 3. Call Denied Tool
        print("\n> Calling 'read_db' (Denied)...")
        try:
            await lilith.call_tool("read_db", {"query": "SELECT *"})
        except PolicyViolationError as e:
            print(f"Blocked: {e}")

if __name__ == "__main__":
    asyncio.run(main())
