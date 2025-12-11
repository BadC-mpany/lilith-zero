import asyncio
import os
import sys

# Ensure we can import sentinel_sdk
sys.path.append(os.path.join(os.getcwd(), "sentinel_sdk", "src"))

from sentinel_sdk import SentinelClient

async def main():
    print("Initializing SentinelClient...")
    try:
        client = SentinelClient(api_key="test_key", base_url="http://localhost:8000")
        print("[OK] Client initialized successfully")
    except Exception as e:
        print(f"[FAIL] Client initialization failed: {e}")
        return

    print("Checking method signatures...")
    methods = ["start_session", "stop_session", "get_tools_config", "execute_tool", "get_langchain_tools"]
    for method in methods:
        if hasattr(client, method):
             print(f"[OK] Method '{method}' exists")
        else:
             print(f"[FAIL] Method '{method}' MISSING")

    print("\nVerification (Static) Complete.")

if __name__ == "__main__":
    asyncio.run(main())
