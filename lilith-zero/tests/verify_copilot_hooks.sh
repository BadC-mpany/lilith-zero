#!/bin/bash
# Lilith Zero — Copilot hook format integration tests
#
# Run after `cargo build` to verify the binary handles Copilot hook events
# correctly. All tests check:
#   1. Exit code is 0 (Copilot ignores exit codes)
#   2. stdout is a single line of valid JSON
#   3. permissionDecision is "allow" or "deny" as expected
#
# Usage: bash tests/verify_copilot_hooks.sh

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
BINARY="$PROJECT_ROOT/target/debug/lilith-zero"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

pass() { echo -e "${GREEN}PASS${NC}  $1"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}FAIL${NC}  $1"; FAIL=$((FAIL + 1)); }
info() { echo -e "${YELLOW}----${NC}  $1"; }

if [ ! -f "$BINARY" ]; then
    echo "Binary not found: $BINARY"
    echo "Run: cargo build"
    exit 1
fi

# ---------------------------------------------------------------------------
# Helper: write a policy file to a temp path and echo the path
# ---------------------------------------------------------------------------
write_policy() {
    local content="$1"
    local tmpfile
    tmpfile="$(mktemp /tmp/lilith-copilot-test-policy-XXXXXX.yaml)"
    echo "$content" > "$tmpfile"
    echo "$tmpfile"
}

# Derive the session file path for a given cwd (mirrors Rust derive_session_id).
# The session file is created by tests 1-8 that use cwd="/workspace".
workspace_session_file() {
    local cwd="$1"
    local sid
    sid="copilot-$(printf '%s' "$cwd" | sha256sum | head -c 32)"
    echo "$HOME/.lilith/sessions/${sid}.json"
}

# Clean up the workspace session file left by non-taint tests, both before
# (so stale state from a previous failed run doesn't interfere) and after.
WORKSPACE_SESSION="$(workspace_session_file "/workspace")"
rm -f "$WORKSPACE_SESSION" 2>/dev/null || true
# Also clean up the Claude backward-compat test session used in test 10.
CLAUDE_COMPAT_SESSION="$HOME/.lilith/sessions/shell-compat.json"
rm -f "$CLAUDE_COMPAT_SESSION" 2>/dev/null || true

DEFAULT_POLICY="$(write_policy '
id: test-policy
customer_id: test
name: Copilot Shell Test Policy
version: 1
static_rules:
  allowed_tool: ALLOW
  forbidden_tool: DENY
taint_rules: []
resource_rules: []
')"

# ---------------------------------------------------------------------------
# Helper: run hook with copilot format, return JSON decision
# ---------------------------------------------------------------------------
run_copilot() {
    local input="$1"
    local event="$2"
    local policy="${3:-$DEFAULT_POLICY}"
    echo "$input" | "$BINARY" hook --format copilot --event "$event" --policy "$policy"
}

# Reads JSON from stdin and extracts permissionDecision.
# Call as: DECISION="$(echo "$RESULT" | get_decision)"
get_decision() {
    python3 -c "import sys, json; d = json.load(sys.stdin); print(d.get('permissionDecision','MISSING'))" 2>/dev/null || echo "INVALID_JSON"
}

# ---------------------------------------------------------------------------
# Test 1: allowed tool returns allow
# ---------------------------------------------------------------------------
info "Test 1: allowed tool → allow"
RESULT="$(run_copilot '{"timestamp":1704614600000,"cwd":"/workspace","toolName":"allowed_tool","toolArgs":"{}"}' "preToolUse")"
DECISION="$(echo "$RESULT" | get_decision)"
if [ "$DECISION" = "allow" ]; then
    pass "allowed_tool → permissionDecision=allow"
else
    fail "allowed_tool → expected allow, got: $DECISION (raw: $RESULT)"
fi

# ---------------------------------------------------------------------------
# Test 2: denied tool returns deny
# ---------------------------------------------------------------------------
info "Test 2: denied tool → deny"
RESULT="$(run_copilot '{"timestamp":1704614600000,"cwd":"/workspace","toolName":"forbidden_tool","toolArgs":"{}"}' "preToolUse")"
DECISION="$(echo "$RESULT" | get_decision)"
if [ "$DECISION" = "deny" ]; then
    pass "forbidden_tool → permissionDecision=deny"
else
    fail "forbidden_tool → expected deny, got: $DECISION (raw: $RESULT)"
fi

# ---------------------------------------------------------------------------
# Test 3: exit code is always 0 (even for deny)
# ---------------------------------------------------------------------------
info "Test 3: exit code is 0 for deny"
EXIT_CODE=0
echo '{"timestamp":1704614600000,"cwd":"/workspace","toolName":"forbidden_tool","toolArgs":"{}"}' | \
    "$BINARY" hook --format copilot --event preToolUse --policy "$DEFAULT_POLICY" > /dev/null || EXIT_CODE=$?
if [ "$EXIT_CODE" -eq 0 ]; then
    pass "deny → exit code 0"
else
    fail "deny → expected exit code 0, got: $EXIT_CODE"
fi

# ---------------------------------------------------------------------------
# Test 4: output is valid single-line JSON
# ---------------------------------------------------------------------------
info "Test 4: output is single-line valid JSON"
RESULT="$(run_copilot '{"timestamp":1704614600000,"cwd":"/workspace","toolName":"allowed_tool","toolArgs":"{}"}' "preToolUse")"
LINE_COUNT="$(echo "$RESULT" | grep -c '.' || true)"
if [ "$LINE_COUNT" -le 1 ]; then
    pass "output is single line"
else
    fail "output has $LINE_COUNT lines (expected 1): $RESULT"
fi
python3 -c "import json,sys; json.loads('''$RESULT''')" 2>/dev/null && pass "output is valid JSON" || fail "output is not valid JSON: $RESULT"

# ---------------------------------------------------------------------------
# Test 5: malformed JSON input → deny (fail-closed)
# ---------------------------------------------------------------------------
info "Test 5: malformed JSON → fail-closed deny"
RESULT="$(echo "{ this is not json" | "$BINARY" hook --format copilot --event preToolUse --policy "$DEFAULT_POLICY")"
DECISION="$(echo "$RESULT" | get_decision)"
if [ "$DECISION" = "deny" ]; then
    pass "malformed JSON → deny (fail-closed)"
else
    fail "malformed JSON → expected deny, got: $DECISION"
fi

# ---------------------------------------------------------------------------
# Test 6: empty stdin → deny (fail-closed)
# ---------------------------------------------------------------------------
info "Test 6: empty stdin → fail-closed deny"
RESULT="$(echo -n "" | "$BINARY" hook --format copilot --event preToolUse --policy "$DEFAULT_POLICY")"
DECISION="$(echo "$RESULT" | get_decision)"
if [ "$DECISION" = "deny" ]; then
    pass "empty stdin → deny (fail-closed)"
else
    fail "empty stdin → expected deny, got: $DECISION"
fi

# ---------------------------------------------------------------------------
# Test 7: sessionStart → allow (output ignored by Copilot)
# ---------------------------------------------------------------------------
info "Test 7: sessionStart → allow (informational)"
RESULT="$(run_copilot '{"timestamp":1704614400000,"cwd":"/workspace","source":"new","initialPrompt":"Build feature"}' "sessionStart")"
DECISION="$(echo "$RESULT" | get_decision)"
if [ "$DECISION" = "allow" ]; then
    pass "sessionStart → allow"
else
    fail "sessionStart → expected allow, got: $DECISION"
fi

# ---------------------------------------------------------------------------
# Test 8: postToolUse → allow (output ignored by Copilot)
# ---------------------------------------------------------------------------
info "Test 8: postToolUse → allow (informational)"
RESULT="$(run_copilot '{"timestamp":1704614700000,"cwd":"/workspace","toolName":"allowed_tool","toolArgs":"{}","toolResult":{"resultType":"success","textResultForLlm":"done"}}' "postToolUse")"
DECISION="$(echo "$RESULT" | get_decision)"
if [ "$DECISION" = "allow" ]; then
    pass "postToolUse → allow"
else
    fail "postToolUse → expected allow, got: $DECISION"
fi

# ---------------------------------------------------------------------------
# Test 9: taint persistence across calls (same cwd)
# ---------------------------------------------------------------------------
info "Test 9: taint persists across calls with same cwd"
TAINT_CWD="/tmp/lilith-shell-test-taint-$$"

TAINT_POLICY="$(write_policy '
id: taint-shell-test
customer_id: test
name: Shell Taint Test
version: 1
static_rules:
  taint_me: ALLOW
  check_me: ALLOW
taint_rules:
  - tool: taint_me
    action: ADD_TAINT
    tag: SHELL_TAINT
  - tool: check_me
    action: CHECK_TAINT
    required_taints: ["SHELL_TAINT"]
    error: "requires SHELL_TAINT"
resource_rules: []
')"

# Compute session ID (mirrors the Rust implementation)
SESSION_ID="copilot-$(echo -n "$TAINT_CWD" | sha256sum | head -c 32)"
SESSION_FILE="$HOME/.lilith/sessions/${SESSION_ID}.json"
rm -f "$SESSION_FILE" 2>/dev/null || true

# Call 1: add taint
run_copilot "{\"timestamp\":1704614600000,\"cwd\":\"$TAINT_CWD\",\"toolName\":\"taint_me\",\"toolArgs\":\"{}\"}" "preToolUse" "$TAINT_POLICY" > /dev/null

# Call 2: check taint — should be denied because taint was added in call 1
RESULT="$(run_copilot "{\"timestamp\":1704614700000,\"cwd\":\"$TAINT_CWD\",\"toolName\":\"check_me\",\"toolArgs\":\"{}\"}" "preToolUse" "$TAINT_POLICY")"
DECISION="$(echo "$RESULT" | get_decision)"
if [ "$DECISION" = "deny" ]; then
    pass "taint persisted across calls with same cwd → check_me denied"
else
    fail "taint persistence failed: check_me → expected deny, got: $DECISION"
fi

# Clean up
rm -f "$SESSION_FILE" "$TAINT_POLICY" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Test 10: Claude format still works (backward compat, no --format flag)
# ---------------------------------------------------------------------------
info "Test 10: Claude format backward compatibility"
CLAUDE_RESULT=0
echo '{"session_id":"shell-compat","hook_event_name":"PreToolUse","tool_name":"allowed_tool","tool_input":{}}' | \
    "$BINARY" hook --policy "$DEFAULT_POLICY" > /dev/null || CLAUDE_RESULT=$?
if [ "$CLAUDE_RESULT" -eq 0 ]; then
    pass "Claude format allowed_tool → exit 0"
else
    fail "Claude format allowed_tool → expected exit 0, got: $CLAUDE_RESULT"
fi

# ---------------------------------------------------------------------------
# Clean up temp files and session files created during this run
# ---------------------------------------------------------------------------
rm -f "$DEFAULT_POLICY"
rm -f "$WORKSPACE_SESSION" "$CLAUDE_COMPAT_SESSION" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
