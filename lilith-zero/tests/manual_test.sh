#!/bin/bash
# Quick manual smoke test for the Copilot hook format.
# Run from lilith-zero/lilith-zero/ after `cargo build`.

set -euo pipefail

BINARY="./target/debug/lilith-zero"
POLICY="./tests/fixtures/policy_test.yaml"

echo "=== Test 1: allowed_tool → expect permissionDecision=allow ==="
echo '{"timestamp":1704614600000,"cwd":"/workspace","toolName":"allowed_tool","toolArgs":"{}"}' \
    | "$BINARY" hook --format copilot --event preToolUse --policy "$POLICY"

echo ""
echo "=== Test 2: forbidden_tool → expect permissionDecision=deny ==="
echo '{"timestamp":1704614600000,"cwd":"/workspace","toolName":"forbidden_tool","toolArgs":"{}"}' \
    | "$BINARY" hook --format copilot --event preToolUse --policy "$POLICY"

echo ""
echo "=== Test 3: Claude format (no --format flag) → expect exit 0 for allowed_tool ==="
echo '{"session_id":"test","hook_event_name":"PreToolUse","tool_name":"allowed_tool","tool_input":{}}' \
    | "$BINARY" hook --policy "$POLICY"
echo "Exit code: $?"
