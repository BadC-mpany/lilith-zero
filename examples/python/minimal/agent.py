"""
Minimal Lilith reference implementation — static allow/deny.

Demonstrates:
  1. SDK initialisation (binary auto-discovery via LILITH_ZERO_BINARY_PATH or PATH)
  2. Tool discovery (list_tools)
  3. Calling an allowed tool
  4. Calling a denied tool → PolicyViolationError
  5. Session ID — HMAC-signed identifier accessible as lilith.session_id

Run:
    export LILITH_ZERO_BINARY_PATH=/path/to/lilith-zero   # or add to PATH
    python agent.py
"""

import asyncio
import os
import sys

from lilith_zero import Lilith, PolicyViolationError

POLICY = os.path.join(os.path.dirname(__file__), "policy.yaml")
SERVER = os.path.join(os.path.dirname(__file__), "server.py")


async def main() -> None:
    # Lilith auto-discovers its binary via LILITH_ZERO_BINARY_PATH env var,
    # PATH, or the standard user install location (~/.lilith_zero/bin).
    async with Lilith(
        upstream=f"{sys.executable} -u {SERVER}",
        policy=POLICY,
    ) as lilith:
        print(f"session  : {lilith.session_id}")

        # --- Tool discovery ---
        tools = await lilith.list_tools()
        print(f"tools    : {[t['name'] for t in tools]}")

        # --- Allowed calls ---
        result = await lilith.call_tool("search_web", {"query": "Lilith Zero MCP security"})
        print(f"search   : {result['content'][0]['text']}")

        result = await lilith.call_tool("get_time", {})
        print(f"time     : {result['content'][0]['text']}")

        # --- Denied call ---
        try:
            await lilith.call_tool("query_database", {"sql": "SELECT * FROM users"})
            print("ERROR: should have been blocked")
        except PolicyViolationError as exc:
            print(f"blocked  : {exc}")


if __name__ == "__main__":
    asyncio.run(main())
