#!/usr/bin/env python3
"""
Minimal test: Send ONE request and check if session file is created.
"""

import requests
import json
import sys
import os
import time
import subprocess

BASE_URL = "https://lilith-zero.badcompany.xyz"
AGENT_ID = "5be3e14e-2e46-f111-bec6-7c1e52344333"

# Use a timestamp-based conversation ID so we can easily find it
CONVERSATION_ID = f"min-test-{int(time.time())}"
SESSION_FILE = os.path.expanduser(f"~/.lilith/sessions/{CONVERSATION_ID}.json")

print("=" * 70)
print("MINIMAL PERSISTENCE TEST")
print("=" * 70)
print(f"Conversation ID: {CONVERSATION_ID}")
print(f"Expected session file: {SESSION_FILE}")
print()

# Send a single request
print("Sending Search-Web request...")
payload = {
    "plannerContext": {
        "userMessage": "test",
        "thought": "test",
        "chatHistory": [],
        "previousToolsOutputs": []
    },
    "toolDefinition": {
        "id": "cra65_otpdemo.action.SearchWeb-SearchWeb",
        "type": "ToolDefinition",
        "name": "Search-Web",
        "description": "Test",
        "inputParameters": [],
        "outputParameters": []
    },
    "inputValues": {"query": "test"},
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

try:
    resp = requests.post(
        f"{BASE_URL}/analyze-tool-execution",
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=10
    )
    print(f"Response: HTTP {resp.status_code}")
    print(f"Body: {json.dumps(resp.json(), indent=2)}")
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)

print()
print("Checking if session file was created...")
time.sleep(0.5)  # Give filesystem a moment to write

if os.path.exists(SESSION_FILE):
    print(f"✓ SESSION FILE EXISTS: {SESSION_FILE}")
    print()
    with open(SESSION_FILE, 'r') as f:
        content = json.load(f)
    print("File contents:")
    print(json.dumps(content, indent=2))

    # Check for taints
    taints = content.get('taints', [])
    if taints:
        print(f"\n✓ Taints found: {taints}")
    else:
        print(f"\n✗ No taints in file (expected UNTRUSTED_SOURCE)")
else:
    print(f"✗ SESSION FILE DOES NOT EXIST")
    print(f"   Expected: {SESSION_FILE}")
    print()
    print("Listing ~/.lilith/sessions/ to see what WAS created:")
    try:
        subprocess.run(["ls", "-lat", os.path.expanduser("~/.lilith/sessions/")],
                      capture_output=False)
    except:
        print("   (Could not list directory)")

print()
print("=" * 70)
