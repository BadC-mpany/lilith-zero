#!/usr/bin/env python3
"""
Debug script to test session persistence.
Sends same conversation_id multiple times and checks if taints persist.
"""

import requests
import json
import sys
import time
from typing import Dict, Any

BASE_URL = "https://lilith-zero.badcompany.xyz"
AGENT_ID = "5be3e14e-2e46-f111-bec6-7c1e52344333"
# Fresh ID each run so there's no stale taint state from previous test runs.
CONVERSATION_ID = f"debug-test-{int(time.time())}"

def send_request(tool_id: str, tool_name: str, input_values: Dict[str, Any]):
    """Send a single webhook request."""
    payload = {
        "plannerContext": {
            "userMessage": f"Test {tool_name}",
            "thought": "Debug test",
            "chatHistory": [],
            "previousToolsOutputs": []
        },
        "toolDefinition": {
            "id": tool_id,
            "type": "ToolDefinition",
            "name": tool_name,
            "description": f"Test: {tool_name}",
            "inputParameters": [],
            "outputParameters": []
        },
        "inputValues": input_values,
        "conversationMetadata": {
            "agent": {
                "id": AGENT_ID,
                "tenantId": "test",
                "environmentId": "test",
                "name": "test",
                "isPublished": True
            },
            "conversationId": CONVERSATION_ID,
            "channelId": "pva-studio"
        }
    }

    print(f"\n{'='*70}")
    print(f"Sending: {tool_name}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    print(f"{'='*70}")

    try:
        resp = requests.post(
            f"{BASE_URL}/analyze-tool-execution",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        print(f"HTTP Status: {resp.status_code}")
        result = resp.json()
        print(f"Response: {json.dumps(result, indent=2)}")
        return result

    except Exception as e:
        print(f"ERROR: {e}")
        return None

if __name__ == "__main__":
    print("\n" + "="*70)
    print("DEBUG: Session Persistence Test")
    print("="*70)
    print(f"Target: {BASE_URL}")
    print(f"Agent: {AGENT_ID}")
    print(f"Conversation: {CONVERSATION_ID}\n")

    # Step 1: Search-Web (should add UNTRUSTED_SOURCE taint)
    print("\n[STEP 1] Search-Web (adds UNTRUSTED_SOURCE)")
    r1 = send_request(
        "cra65_otpdemo.action.SearchWeb-SearchWeb",
        "Search-Web",
        {"query": "test"}
    )

    # Step 2: Send-Email (should be allowed without other taint)
    print("\n[STEP 2] Send-Email (with only UNTRUSTED_SOURCE, should allow)")
    r2 = send_request(
        "cra65_otpdemo.action.SendEmail-SendEmail",
        "Send-Email",
        {"to": "test@example.com"}
    )

    # Step 3: Read-Emails (should add ACCESS_PRIVATE taint)
    print("\n[STEP 3] Read-Emails (adds ACCESS_PRIVATE)")
    r3 = send_request(
        "cra65_otpdemo.action.ReadEmails-ReadEmails",
        "Read-Emails",
        {"folder": "Inbox"}
    )

    # Step 4: Send-Email AGAIN (should now be blocked with both taints)
    print("\n[STEP 4] Send-Email again (with both taints, should BLOCK)")
    r4 = send_request(
        "cra65_otpdemo.action.SendEmail-SendEmail",
        "Send-Email",
        {"to": "test@example.com"}
    )

    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print("\nResults:")
    if r1:
        print(f"[1] Search-Web:  blockAction={r1.get('blockAction', '?')}")
        if r1.get('diagnostics'):
            print(f"    Diagnostics: {r1['diagnostics']}")
    if r2:
        print(f"[2] Send-Email:  blockAction={r2.get('blockAction', '?')} (should be False)")
        if r2.get('diagnostics'):
            print(f"    Diagnostics: {r2['diagnostics']}")
    if r3:
        print(f"[3] Read-Emails: blockAction={r3.get('blockAction', '?')}")
        if r3.get('diagnostics'):
            print(f"    Diagnostics: {r3['diagnostics']}")
    if r4:
        print(f"[4] Send-Email:  blockAction={r4.get('blockAction', '?')} (should be True - LETHAL TRIFECTA)")
        if r4.get('diagnostics'):
            print(f"    Diagnostics: {r4['diagnostics']}")
        if r4.get('reason'):
            print(f"    Reason: {r4['reason']}")

        if r4.get('blockAction'):
            print("\n✓ PASS: Lethal trifecta blocking works!")
        else:
            print("\n✗ FAIL: Lethal trifecta NOT blocking!")
            print("   Possible causes:")
            print("   1. Taints are not being persisted between requests")
            print("   2. Taints are not being loaded on subsequent requests")
            print("   3. Cedar policy rule is not matching correctly")
            print("   4. Session storage directory is not writable on Azure")
