"""
Calculator Lilith reference implementation — static allow/deny, resource ACL.

Shows how Lilith wraps any MCP server transparently (here a simple calculator
server; in production this would be your FastMCP, mcp-python, or any other
stdio MCP server).

Demonstrates:
  1. Tool discovery
  2. Allowed tool calls (add, multiply, sqrt)
  3. Static DENY — divide() blocked at policy level
  4. Resource read — constants://* allowed
  5. Resource ACL — constants://* readable

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
    async with Lilith(
        upstream=f"{sys.executable} -u {SERVER}",
        policy=POLICY,
    ) as lilith:
        print(f"session  : {lilith.session_id}")

        tools = await lilith.list_tools()
        resources = await lilith.list_resources()
        print(f"tools    : {[t['name'] for t in tools]}")
        print(f"resources: {[r['uri'] for r in resources]}")

        # --- Allowed tool calls ---
        result = await lilith.call_tool("add", {"a": 7, "b": 3})
        raw = result["content"][0]["text"]
        print(f"\nadd(7, 3)      = {raw}")

        result = await lilith.call_tool("multiply", {"a": 6, "b": 7})
        print(f"multiply(6, 7) = {result['content'][0]['text']}")

        result = await lilith.call_tool("sqrt", {"x": 144.0})
        print(f"sqrt(144)      = {result['content'][0]['text']}")

        # --- Static DENY ---
        print("\n> Calling divide() — blocked by policy:")
        try:
            await lilith.call_tool("divide", {"a": 10, "b": 2})
            print("  ERROR: should have been blocked")
        except PolicyViolationError as exc:
            print(f"  blocked ✓: {exc}")

        # --- Resource read ---
        pi = await lilith.read_resource("constants://pi")
        print(f"\nconstants://pi : {pi['contents'][0]['text']}")

        e_const = await lilith.read_resource("constants://e")
        print(f"constants://e  : {e_const['contents'][0]['text']}")

    print("\n✓ Done")


if __name__ == "__main__":
    asyncio.run(main())
