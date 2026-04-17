"""
Agentic loop Lilith reference implementation — multi-turn agent with taint tracking.

Simulates a multi-turn AI agent loop (as used in LangChain, AutoGen, CrewAI, etc.)
where an agent iteratively calls tools based on prior results.  Lilith enforces
the security policy on every tool call regardless of which framework drives them.

Demonstrates:
  1. Multi-turn loop — agent makes sequential tool decisions across turns
  2. Taint source — database() adds SENSITIVE_CONTEXT taint
  3. Taint sink — web_search() blocked once SENSITIVE_CONTEXT is active
  4. Static DENY — delete_record() never allowed regardless of session state
  5. Safe tool — calculator() unaffected by any taint
  6. Audit log — every allow and deny is signed and captured

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


def section(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


# Simulated agent "plan" — the sequence of decisions an LLM would make.
# In a real system these would be LLM tool_calls; here they are hardcoded
# to make the example deterministic and runnable without an API key.
AGENT_STEPS = [
    ("calculator",    {"expression": "42 * 1337"},   "safe math"),
    ("database",      {"query": "active customers"},  "read internal data → taints session"),
    ("web_search",    {"query": "customer revenue"},  "attempt exfiltration → blocked"),
    ("delete_record", {"record_id": "1001"},          "destructive → statically denied"),
    ("calculator",    {"expression": "2 ** 10"},      "safe call still works after blocks"),
]


async def main() -> None:
    async with Lilith(
        upstream=f"{sys.executable} -u {SERVER}",
        policy=POLICY,
    ) as lilith:
        print(f"session  : {lilith.session_id}")
        tools = await lilith.list_tools()
        print(f"tools    : {[t['name'] for t in tools]}")

        section("Agent loop — simulating multi-turn LLM tool calls")

        for i, (tool_name, args, note) in enumerate(AGENT_STEPS, 1):
            print(f"\n  turn {i}: {tool_name}({args})  [{note}]")
            try:
                async with lilith.span(f"turn-{i}"):
                    result = await lilith.call_tool(tool_name, args)
                text = result["content"][0]["text"]
                print(f"    allowed ✓: {text[:70]}")
            except PolicyViolationError as exc:
                print(f"    blocked ✓: {exc}")

        section("Audit trail")
        logs = await lilith.drain_audit_logs()
        print(f"  total events: {len(logs)}")
        for entry in logs:
            decision = entry.get("details", {}).get("decision", entry["event_type"])
            tool = entry.get("details", {}).get("tool_name", "—")
            print(f"    [{decision:30}] {tool}")

    print("\n✓ Done")


if __name__ == "__main__":
    asyncio.run(main())
