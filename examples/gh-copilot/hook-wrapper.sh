#!/bin/bash
# Lilith Zero — hook wrapper for gh copilot CLI
#
# This script is invoked by gh copilot for every tool call.
# It finds the lilith-zero binary and forwards stdin to the policy engine.
#
# Required env vars (set via hooks.json "env" field or export):
#   LILITH_ZERO_BIN      Absolute path to the lilith-zero binary.
#                        Falls back to 'lilith-zero' on PATH.
#   LILITH_ZERO_EVENT    The hook event name: preToolUse, postToolUse, etc.
#                        Set automatically from hooks.json.
#   LILITH_ZERO_POLICY   Path to the policy YAML file.
#
# Output format for gh copilot CLI: {"permissionDecision": "allow"/"deny"}

set -euo pipefail

# Fail-closed: on any error, deny the action
deny() {
    local reason="${1:-internal error}"
    local escaped
    escaped=$(printf '%s' "$reason" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '{"permissionDecision":"deny","permissionDecisionReason":"%s"}\n' "$escaped"
    exit 0
}

# Locate binary
LILITH_BIN="${LILITH_ZERO_BIN:-$(command -v lilith-zero 2>/dev/null || true)}"
[ -z "$LILITH_BIN" ] && deny "lilith-zero binary not found — set LILITH_ZERO_BIN"
[[ "$LILITH_BIN" != /* ]] && deny "LILITH_ZERO_BIN must be an absolute path"
[ ! -x "$LILITH_BIN" ] && deny "lilith-zero not executable at: $LILITH_BIN"

# Validate event name
EVENT="${LILITH_ZERO_EVENT:-}"
[ -z "$EVENT" ] && deny "LILITH_ZERO_EVENT not set"
case "$EVENT" in
    preToolUse|postToolUse|sessionStart|sessionEnd|userPromptSubmitted|errorOccurred) ;;
    *) deny "Invalid LILITH_ZERO_EVENT: $EVENT" ;;
esac

# Policy args
POLICY_ARGS=()
if [ -n "${LILITH_ZERO_POLICY:-}" ] && [ -f "$LILITH_ZERO_POLICY" ]; then
    POLICY_ARGS=(--policy "$LILITH_ZERO_POLICY")
fi

# Audit log args
AUDIT_ARGS=()
if [ -n "${LILITH_ZERO_AUDIT:-}" ]; then
    AUDIT_ARGS=(--audit-logs "$LILITH_ZERO_AUDIT")
fi

# Run — stdin is forwarded automatically via exec
exec "$LILITH_BIN" hook \
    --format copilot \
    --event "$EVENT" \
    "${POLICY_ARGS[@]}" \
    "${AUDIT_ARGS[@]}"
