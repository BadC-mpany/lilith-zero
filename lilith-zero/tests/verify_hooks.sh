#!/bin/bash
set -e

# Base paths relative to script location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

# Ensure we use the debug binary from project root
BINARY="$PROJECT_ROOT/target/debug/lilith-zero"

echo "--- Testing Allowed Hook ---"
cat "$FIXTURES_DIR/hook_input_allow.json" | "$BINARY" hook --policy "$FIXTURES_DIR/policy_test.yaml"
echo "Exit code: $?"

echo "--- Testing Blocked Hook ---"
set +e
cat "$FIXTURES_DIR/hook_input_block.json" | "$BINARY" hook --policy "$FIXTURES_DIR/policy_test.yaml"
EXIT_CODE=$?
set -e
echo "Exit code: $EXIT_CODE"

if [ $EXIT_CODE -eq 2 ]; then
    echo "SUCCESS: Blocked hook returned exit code 2"
else
    echo "FAILURE: Blocked hook returned exit code $EXIT_CODE (expected 2)"
    exit 1
fi

echo "--- Testing State Persistence ---"

# Use a unique session ID per run so orphan files from a failed previous run
# never affect this run (and this run's files don't affect the next).
SESSION_ID="test-persist-$$"
SESSION_FILE="$HOME/.lilith/sessions/${SESSION_ID}.json"
rm -f "$SESSION_FILE" 2>/dev/null || true

POLICY_PERSISTENCE="$(mktemp /tmp/lilith-persist-policy-XXXXXX.yaml)"
cat > "$POLICY_PERSISTENCE" <<EOF
id: persistence-policy
customer_id: test-customer
name: Persistence Test Policy
version: 1
static_rules:
  taint_me: ALLOW
  check_me: ALLOW
taint_rules:
  - tool: taint_me
    action: ADD_TAINT
    tag: PERSISTENT_TAINT
  - tool: check_me
    action: CHECK_TAINT
    required_taints: ["PERSISTENT_TAINT"]
    error: "Blocked by persistent taint"
resource_rules: []
EOF

echo "1. Call taint_me"
echo "{\"session_id\": \"$SESSION_ID\", \"hook_event_name\": \"PreToolUse\", \"tool_name\": \"taint_me\"}" | "$BINARY" hook --policy "$POLICY_PERSISTENCE"
echo "Exit code: $?"

echo "2. Call check_me (should be blocked)"
set +e
echo "{\"session_id\": \"$SESSION_ID\", \"hook_event_name\": \"PreToolUse\", \"tool_name\": \"check_me\"}" | "$BINARY" hook --policy "$POLICY_PERSISTENCE"
EXIT_CODE_PERSIST=$?
set -e
echo "Exit code: $EXIT_CODE_PERSIST"

rm -f "$POLICY_PERSISTENCE" "$SESSION_FILE" 2>/dev/null || true

if [ $EXIT_CODE_PERSIST -eq 2 ]; then
    echo "SUCCESS: Persistence verified across calls"
else
    echo "FAILURE: Persistence failed (expected 2)"
    exit 1
fi
