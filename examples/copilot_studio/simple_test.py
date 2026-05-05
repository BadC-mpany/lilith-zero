#!/usr/bin/env python3
import requests, json, os, time

url = "https://lilith-zero.badcompany.xyz/analyze-tool-execution"
conv_id = "simple-test-xyz"
agent_id = "5be3e14e-2e46-f111-bec6-7c1e52344333"

payload = {
    "plannerContext": {"userMessage": "test", "thought": "test", "chatHistory": [], "previousToolsOutputs": []},
    "toolDefinition": {"id": "cra65_otpdemo.action.SearchWeb-SearchWeb", "type": "ToolDefinition", "name": "Search-Web", "description": "Test", "inputParameters": [], "outputParameters": []},
    "inputValues": {"query": "test"},
    "conversationMetadata": {"agent": {"id": agent_id, "tenantId": "test", "environmentId": "test", "name": "test", "isPublished": True}, "conversationId": conv_id, "channelId": "pva-studio"}
}

resp = requests.post(url, json=payload)
print(f"Response: {resp.status_code} - {resp.json()}")

time.sleep(0.5)
session_file = os.path.expanduser(f"~/.lilith/sessions/{conv_id}.json")
if os.path.exists(session_file):
    with open(session_file) as f:
        content = json.load(f)
    print(f"✓ File created: {conv_id}.json")
    print(f"  Taints: {content.get('taints', [])}")
else:
    print(f"✗ NO FILE: {conv_id}.json")
    # Check what WAS created
    result = os.popen("ls -t ~/.lilith/sessions | head -3").read()
    print(f"  Latest files:\n{result}")
