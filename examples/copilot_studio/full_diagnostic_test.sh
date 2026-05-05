#!/bin/bash
set -e

echo "=================================================="
echo "LILITH ZERO WEBHOOK DIAGNOSTIC TEST"
echo "=================================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Check session directory
echo "TEST 1: Check session storage directory"
echo "--------------------------------------"
SESSION_DIR="${HOME}/.lilith/sessions"
if [ -d "$SESSION_DIR" ]; then
    echo -e "${GREEN}✓${NC} Directory exists: $SESSION_DIR"
    echo "  Contents:"
    ls -lah "$SESSION_DIR" 2>/dev/null || echo "  (empty or not readable)"
    BEFORE_COUNT=$(find "$SESSION_DIR" -name "*.json" 2>/dev/null | wc -l)
    echo "  Files before test: $BEFORE_COUNT"
else
    echo -e "${YELLOW}!${NC} Directory does NOT exist: $SESSION_DIR"
    echo "  Will create during test"
    BEFORE_COUNT=0
fi
echo ""

# Test 2: Check if policy file exists
echo "TEST 2: Check Cedar policy file"
echo "--------------------------------------"
POLICY_FILE="examples/copilot_studio/policies/policy_5be3e14e-2e46-f111-bec6-7c1e52344333.cedar"
if [ -f "$POLICY_FILE" ]; then
    echo -e "${GREEN}✓${NC} Policy file exists"
    TAINT_RULES=$(grep -c "add_taint:" "$POLICY_FILE" || true)
    echo "  Taint rules found: $TAINT_RULES"
    LETHAL_RULE=$(grep -c "lethal_trifecta" "$POLICY_FILE" || true)
    echo "  Lethal trifecta rule: $([[ $LETHAL_RULE -gt 0 ]] && echo "YES" || echo "NO")"
else
    echo -e "${RED}✗${NC} Policy file NOT found: $POLICY_FILE"
fi
echo ""

# Test 3: Run the diagnostic test
echo "TEST 3: Running taint persistence test"
echo "--------------------------------------"
echo "Sending 4 requests to Azure webhook..."
echo ""

python3 - <<'EOF'
import requests
import json
import sys

BASE_URL = "https://lilith-zero.badcompany.xyz"
AGENT_ID = "5be3e14e-2e46-f111-bec6-7c1e52344333"
CONVERSATION_ID = f"diagnostic-test-{__import__('time').time()}"

def send_request(tool_id, tool_name, input_values):
    payload = {
        "plannerContext": {
            "userMessage": f"Test {tool_name}",
            "thought": "Diagnostic test",
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

    try:
        resp = requests.post(
            f"{BASE_URL}/analyze-tool-execution",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        return resp.status_code, resp.json()
    except Exception as e:
        return None, {"error": str(e)}

# Step 1
status, result = send_request("cra65_otpdemo.action.SearchWeb-SearchWeb", "Search-Web", {"query": "test"})
print(f"[1] Search-Web: {status} - blockAction={result.get('blockAction', '?')}")

# Step 2
status, result = send_request("cra65_otpdemo.action.SendEmail-SendEmail", "Send-Email", {"to": "test@example.com"})
print(f"[2] Send-Email: {status} - blockAction={result.get('blockAction', '?')} (should be False)")

# Step 3
status, result = send_request("cra65_otpdemo.action.ReadEmails-ReadEmails", "Read-Emails", {"folder": "Inbox"})
print(f"[3] Read-Emails: {status} - blockAction={result.get('blockAction', '?')}")

# Step 4 - THIS SHOULD BE BLOCKED
status, result = send_request("cra65_otpdemo.action.SendEmail-SendEmail", "Send-Email", {"to": "test@example.com"})
print(f"[4] Send-Email: {status} - blockAction={result.get('blockAction', '?')} (should be True - LETHAL TRIFECTA)")

if result.get('blockAction'):
    print("\n✓ SUCCESS: Lethal trifecta is working!")
else:
    print("\n✗ FAIL: Taints are not persisting")
    print(f"   Conversation ID: {CONVERSATION_ID}")

EOF

echo ""

# Test 4: Check if session files were created
echo "TEST 4: Check if session files were created"
echo "--------------------------------------"
if [ -d "$SESSION_DIR" ]; then
    AFTER_COUNT=$(find "$SESSION_DIR" -name "*.json" 2>/dev/null | wc -l)
    echo "Files after test: $AFTER_COUNT"
    if [ $AFTER_COUNT -gt $BEFORE_COUNT ]; then
        echo -e "${GREEN}✓${NC} New session file(s) created!"
        echo ""
        echo "Session file contents:"
        ls -1 "$SESSION_DIR"/*.json | tail -1 | xargs cat | python3 -m json.tool
    else
        echo -e "${RED}✗${NC} No new session files created!"
        echo "   This means persistence is NOT working on the webhook"
    fi
else
    echo -e "${RED}✗${NC} Session directory does not exist"
    echo "   Files are not being created at all"
fi
echo ""

echo "=================================================="
echo "DIAGNOSTIC COMPLETE"
echo "=================================================="
