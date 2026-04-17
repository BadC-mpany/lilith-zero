"""
HTTP transport Lilith reference implementation.

Demonstrates Lilith proxying a Streamable HTTP MCP server (2025-11-25) instead
of a stdio child process.  Policy enforcement is identical to the stdio case —
the transport is the only difference.

What this shows:
  1. Start a local HTTP MCP server (server.py)
  2. Connect Lilith with --transport http → --upstream-url
  3. list_tools, allowed call, denied call (PolicyViolationError)
  4. Session ID and audit log — same guarantees as stdio

Run:
    export LILITH_ZERO_BINARY_PATH=/path/to/lilith-zero
    python agent.py
"""

import asyncio
import os
import sys
import time
from threading import Thread

from lilith_zero import Lilith, PolicyViolationError

# Import the embedded server so we can start it in-process.
sys.path.insert(0, os.path.dirname(__file__))
import server as _srv

POLICY = os.path.join(os.path.dirname(__file__), "policy.yaml")
SERVER_URL = f"http://{_srv.HOST}:{_srv.PORT}/mcp"


async def main() -> None:
    # Start the HTTP MCP server in a background daemon thread.
    httpd = _srv.serve(daemon=True)
    time.sleep(0.1)  # let the socket bind

    try:
        async with Lilith(
            upstream_url=SERVER_URL,
            policy=POLICY,
        ) as lilith:
            print(f"transport : HTTP → {SERVER_URL}")
            print(f"session   : {lilith.session_id}")

            tools = await lilith.list_tools()
            print(f"tools     : {[t['name'] for t in tools]}")

            result = await lilith.call_tool("search_web", {"query": "MCP security"})
            print(f"search    : {result['content'][0]['text']}")

            result = await lilith.call_tool("get_time", {})
            print(f"time      : {result['content'][0]['text']}")

            try:
                await lilith.call_tool("query_database", {"sql": "SELECT * FROM users"})
                print("ERROR: should have been blocked")
            except PolicyViolationError as exc:
                print(f"blocked   : {exc}")

            audit = await lilith.drain_audit_logs()
            print(f"\naudit     : {len(audit)} entries, "
                  f"{sum(1 for e in audit if e.get('signature'))} signed")
            for e in audit:
                dec = e.get("details", {}).get("decision", e.get("event_type", "?"))
                tool = e.get("details", {}).get("tool_name", "")
                print(f"  [{dec:<6}] {tool}")

    finally:
        httpd.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
