"""Debug test to understand handshake timing."""
import asyncio
import logging
import os
import sys

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)s %(message)s')

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from sentinel_sdk import Sentinel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SENTINEL_BIN = os.path.abspath(os.path.join(BASE_DIR, "../../sentinel/target/debug/sentinel.exe"))


async def main():
    print("Starting debug test...")
    
    # Test WITHOUT policy first
    print("\n=== TEST 1: Without Policy ===")
    try:
        async with Sentinel(
            f"{sys.executable} {os.path.join(BASE_DIR, 'mock_server.py')}",
            binary=SENTINEL_BIN,
        ) as sentinel:
            print(f"Session: {sentinel.session_id}")
            tools = await sentinel.list_tools()
            print(f"Tools: {[t['name'] for t in tools]}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test WITH policy
    print("\n=== TEST 2: With Policy ===")
    try:
        async with Sentinel(
            f"{sys.executable} {os.path.join(BASE_DIR, 'mock_server.py')}",
            binary=SENTINEL_BIN,
            policy=os.path.join(BASE_DIR, "policy.yaml"),
        ) as sentinel:
            print(f"Session: {sentinel.session_id}")
            tools = await sentinel.list_tools()
            print(f"Tools: {[t['name'] for t in tools]}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
