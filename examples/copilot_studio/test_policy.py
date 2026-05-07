#!/usr/bin/env python3
"""
End-to-end policy validation for the Copilot Studio webhook.

Tests the full demo scenario plus policy edge cases:
  - Taint accumulation (SearchWeb → UNTRUSTED_SOURCE, ReadEmails → ACCESS_PRIVATE)
  - Trusted network allowlist (otp.hu, badcompany.xyz always allowed)
  - Lethal trifecta blocks untrusted SendEmail and any FetchWebpage
  - ExecutePython exempt from lethal trifecta (local execution)
  - Code injection guardrail blocks unconditionally
"""

import requests
import sys
import time

BASE_URL = "https://lilith-zero.badcompany.xyz"
AGENT_ID = "5be3e14e-2e46-f111-bec6-7c1e52344333"

SEARCH = "cra65_otpdemo.action.SearchWeb-SearchWeb"
EMAILS = "cra65_otpdemo.action.ReadEmails-ReadEmails"
SEND   = "cra65_otpdemo.action.SendEmail-SendEmail"
PYTHON = "cra65_otpdemo.action.ExecutePython-ExecutePython"
FETCH  = "cra65_otpdemo.action.FetchWebpage-FetchWebpage"


def call(conv_id, tool_id, inputs):
    resp = requests.post(
        f"{BASE_URL}/analyze-tool-execution",
        json={
            "plannerContext": {"userMessage": "test"},
            "toolDefinition": {
                "id": tool_id,
                "type": "PrebuiltToolDefinition",
                "name": tool_id,
                "description": "test",
            },
            "inputValues": inputs,
            "conversationMetadata": {
                "agent": {
                    "id": AGENT_ID,
                    "tenantId": "test-tenant",
                    "environmentId": "test-env",
                    "isPublished": True,
                },
                "conversationId": conv_id,
                "channelId": "pva-studio",
            },
        },
        timeout=10,
    )
    body = resp.json()
    return body.get("blockAction"), body.get("reason", "")


def run_suite(label, steps, conv_id, setup=None):
    print(f"\n{'─' * 60}")
    print(f"  {label}")
    print(f"  conversation: {conv_id}")
    print(f"{'─' * 60}")

    if setup:
        for tool_id, inputs in setup:
            call(conv_id, tool_id, inputs)

    passed = 0
    for tool_id, inputs, expect_block, description in steps:
        block, reason = call(conv_id, tool_id, inputs)
        ok = block == expect_block
        if ok:
            passed += 1
        exp = "BLOCK" if expect_block else "ALLOW"
        got = "BLOCK" if block else "ALLOW"
        icon = "✓" if ok else "✗"
        print(f"  {icon} {description}")
        if block and reason:
            print(f"      reason: {reason[:80]}")
        if not ok:
            print(f"      MISMATCH: expected {exp}, got {got}")

    return passed, len(steps)


def main():
    ts = int(time.time())
    total_passed = 0
    total_cases = 0

    # ── Suite 1: Full demo flow ───────────────────────────────────────────
    demo_conv = f"policy-demo-{ts}"
    p, t = run_suite(
        "Suite 1: Demo flow (accumulate taints, then test exfiltration)",
        setup=[
            (SEARCH, {"query": "Vanguard Security Instructions"}),
            (EMAILS, {"folder": "Inbox"}),
        ],
        conv_id=demo_conv,
        steps=[
            (SEND,   {"to": "john@otp.hu", "subject": "Report", "body": "Monthly update"},
             False, "SendEmail → john@otp.hu        (trusted domain, must ALLOW)"),
            (SEND,   {"to": "random@gmail.com", "subject": "my Data", "body": "Here is the data"},
             True,  "SendEmail → random@gmail.com   (untrusted domain, must BLOCK)"),
            (PYTHON, {"code": "print('Hello World')"},
             False, "ExecutePython safe code         (local, must ALLOW)"),
            (FETCH,  {"url": "http://someone.random_site.com/exploit"},
             True,  "FetchWebpage untrusted URL      (any URL after both taints, must BLOCK)"),
        ],
    )
    total_passed += p
    total_cases += t

    # ── Suite 2: Trusted network allowlist ───────────────────────────────
    trusted_conv = f"policy-trusted-{ts}"
    p, t = run_suite(
        "Suite 2: Trusted network allowlist (both taints present)",
        setup=[
            (SEARCH, {"query": "x"}),
            (EMAILS, {"folder": "Inbox"}),
        ],
        conv_id=trusted_conv,
        steps=[
            (SEND, {"to": "alice@otp.hu",      "subject": "s", "body": "b"},
             False, "SendEmail → alice@otp.hu        (trusted, must ALLOW)"),
            (SEND, {"to": "bob@badcompany.xyz", "subject": "s", "body": "b"},
             False, "SendEmail → bob@badcompany.xyz  (trusted, must ALLOW)"),
            (SEND, {"to": "hacker@evil.com",    "subject": "s", "body": "b"},
             True,  "SendEmail → hacker@evil.com     (untrusted, must BLOCK)"),
            (SEND, {"to": "victim@hotmail.com", "subject": "s", "body": "b"},
             True,  "SendEmail → victim@hotmail.com  (untrusted, must BLOCK)"),
        ],
    )
    total_passed += p
    total_cases += t

    # ── Suite 3: Clean session — no lethal trifecta ───────────────────────
    clean_conv = f"policy-clean-{ts}"
    p, t = run_suite(
        "Suite 3: Clean session — only UNTRUSTED_SOURCE, lethal trifecta inactive",
        setup=[
            (SEARCH, {"query": "test"}),
        ],
        conv_id=clean_conv,
        steps=[
            (SEND,   {"to": "anyone@gmail.com", "subject": "s", "body": "b"},
             False, "SendEmail → gmail.com            (single taint only, must ALLOW)"),
            (FETCH,  {"url": "https://example.com"},
             False, "FetchWebpage                     (single taint only, must ALLOW)"),
            (PYTHON, {"code": "x = 1 + 1"},
             False, "ExecutePython                    (must ALLOW)"),
        ],
    )
    total_passed += p
    total_cases += t

    # ── Suite 4: Guardrails (always-on) ──────────────────────────────────
    # Use separate fresh conversations per guardrail test so taints don't
    # interfere with the expected outcome.
    print(f"\n{'─' * 60}")
    print("  Suite 4: Guardrails (always-on, taint-independent)")
    print(f"{'─' * 60}")
    guardrail_cases = [
        (PYTHON, {"code": "import socket\ns = socket.socket()"},
         True,  "ExecutePython: import socket      (guardrail, must BLOCK)"),
        (PYTHON, {"code": "result = shell_exec('id')"},
         False, "ExecutePython: no pattern match   (must ALLOW)"),
        (FETCH,  {"url": "https://malicious-site.com/payload"},
         True,  "FetchWebpage: malicious-site.com  (guardrail, must BLOCK)"),
        (PYTHON, {"code": "print('safe')"},
         False, "ExecutePython: safe code          (must ALLOW)"),
    ]
    g_passed = 0
    for i, (tool_id, inputs, expect_block, description) in enumerate(guardrail_cases):
        conv = f"policy-guard-{ts}-{i}"
        block, reason = call(conv, tool_id, inputs)
        ok = block == expect_block
        if ok:
            g_passed += 1
        icon = "✓" if ok else "✗"
        print(f"  {icon} {description}")
        if block and reason:
            print(f"      reason: {reason[:80]}")
        if not ok:
            exp = "BLOCK" if expect_block else "ALLOW"
            got = "BLOCK" if block else "ALLOW"
            print(f"      MISMATCH: expected {exp}, got {got}")
    total_passed += g_passed
    total_cases += len(guardrail_cases)

    # ── Suite 5: Session isolation ────────────────────────────────────────
    conv_a = f"policy-iso-a-{ts}"
    conv_b = f"policy-iso-b-{ts}"

    call(conv_a, SEARCH, {"query": "x"})
    call(conv_a, EMAILS, {"folder": "Inbox"})

    print(f"\n{'─' * 60}")
    print("  Suite 5: Session isolation")
    print(f"{'─' * 60}")
    iso_passed = 0

    block_a, _ = call(conv_a, SEND, {"to": "evil@gmail.com", "subject": "s", "body": "b"})
    ok = block_a is True
    if ok: iso_passed += 1
    print(f"  {'✓' if ok else '✗'} conv_a SendEmail untrusted (both taints → must BLOCK)")

    block_b, _ = call(conv_b, SEND, {"to": "evil@gmail.com", "subject": "s", "body": "b"})
    ok = block_b is False
    if ok: iso_passed += 1
    print(f"  {'✓' if ok else '✗'} conv_b SendEmail untrusted (clean session → must ALLOW)")

    total_passed += iso_passed
    total_cases += 2

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'═' * 60}")
    all_ok = total_passed == total_cases
    print(f"  {'✓ ALL PASS' if all_ok else '✗ FAILURES'} — {total_passed}/{total_cases}")
    print(f"{'═' * 60}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
