"""
Advanced Lilith reference implementation — taint tracking, conditional rules, resource ACL.

Demonstrates every major Lilith SDK feature:
  1. Taint source    — read_report() adds CONFIDENTIAL taint to the session
  2. Taint sink      — post_to_slack() blocked while CONFIDENTIAL taint is active
  3. Taint cleaner   — redact() removes CONFIDENTIAL taint; subsequent post allowed
  4. Conditional     — archive() blocked unless confirmed=true (tool_args_match exception)
  5. Resource ACL    — reports://public/* readable; reports://confidential/* readable but taints
  6. Audit logs      — Lilith emits HMAC-signed JSONL; accessible via lilith.audit_logs
  7. Spans           — logical grouping for telemetry-linked deployments

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

        # ── 1. Taint source ──────────────────────────────────────────────
        section("1 · Taint source: read_report() adds CONFIDENTIAL taint")
        result = await lilith.call_tool("read_report", {"path": "q3_financials.txt"})
        print(f"  ok: {result['content'][0]['text'][:60]}...")

        # ── 2. Taint sink — blocked ───────────────────────────────────────
        section("2 · Taint sink: post_to_slack() BLOCKED (CONFIDENTIAL active)")
        try:
            await lilith.call_tool("post_to_slack", {"text": "Revenue is $42M!"})
            print("  ERROR: should have been blocked")
        except PolicyViolationError as exc:
            print(f"  blocked ✓: {exc}")

        # ── 3. Neutral tool unaffected ────────────────────────────────────
        section("3 · Neutral tool: summarize() is unaffected by taint")
        result = await lilith.call_tool("summarize", {"text": "Revenue is $42M for Q3."})
        print(f"  ok: {result['content'][0]['text']}")

        # ── 4. Taint cleaner — scrub then re-allow sink ───────────────────
        section("4 · Taint cleaner: redact() removes CONFIDENTIAL; post now allowed")
        result = await lilith.call_tool("redact", {"text": "INTERNAL revenue $42M Q3"})
        print(f"  redacted: {result['content'][0]['text']}")

        result = await lilith.call_tool("post_to_slack", {"text": "Report summary ready."})
        print(f"  posted ✓: {result['content'][0]['text']}")

        # ── 5. Conditional block ──────────────────────────────────────────
        section("5 · Conditional: archive() blocked; allowed with confirmed=true")
        try:
            await lilith.call_tool("archive", {"path": "q3_financials.txt"})
            print("  ERROR: should have been blocked")
        except PolicyViolationError as exc:
            print(f"  blocked ✓: {exc}")

        result = await lilith.call_tool(
            "archive", {"path": "q3_financials.txt", "confirmed": True}
        )
        print(f"  allowed ✓: {result['content'][0]['text']}")

        # ── 6. Resource ACL ───────────────────────────────────────────────
        section("6 · Resource ACL: public readable; confidential readable but taints")

        pub = await lilith.read_resource("reports://public/q3_press_release.txt")
        print(f"  public ✓: {pub['contents'][0]['text']}")

        # Reading a confidential resource re-adds the CONFIDENTIAL taint
        conf = await lilith.read_resource("reports://confidential/q3_full_financials.txt")
        print(f"  confidential ✓: {conf['contents'][0]['text'][:50]}...")

        # Session is tainted again — post to Slack must fail
        try:
            await lilith.call_tool("post_to_slack", {"text": "Earnings call notes"})
            print("  ERROR: should have been blocked after confidential resource read")
        except PolicyViolationError as exc:
            print(f"  re-blocked ✓: taint reinstated by resource read")

        # ── 7. Spans (telemetry grouping) ─────────────────────────────────
        section("7 · Spans: logical grouping (no-op without telemetry link)")
        async with lilith.span("document-processing"):
            result = await lilith.call_tool("redact", {"text": "Some text"})
            print(f"  within span: {result['content'][0]['text'][:40]}")

        # ── 8. Audit logs ─────────────────────────────────────────────────
        section("8 · Audit logs")
        logs = await lilith.drain_audit_logs()
        print(f"  total events captured: {len(logs)}")
        for entry in logs[:3]:
            print(f"    [{entry['event_type']}] {str(entry.get('details', {}))[:60]}")

    print("\n✓ Done")


if __name__ == "__main__":
    asyncio.run(main())
