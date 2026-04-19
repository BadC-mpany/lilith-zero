#!/bin/bash
# Lilith Zero — hook wrapper for VS Code Copilot sidebar agent mode
#
# Invoked by VS Code for every tool call (PreToolUse, PostToolUse, etc.).
# VS Code embeds the event name in the JSON payload — no --event flag needed.
#
# Required env vars (set via hooks.json "env" field or export):
#   LILITH_ZERO_BIN      Absolute path to the lilith-zero binary.
#   LILITH_ZERO_POLICY   Path to the policy YAML file.
#
# Output format for VS Code: {"hookSpecificOutput": {"hookEventName": "...", "permissionDecision": "..."}}

set -euo pipefail

# Fail-closed: on any error, deny using the VS Code output format
deny() {
    local reason="${1:-internal error}"
    local escaped
    escaped=$(printf '%s' "$reason" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$escaped"
    exit 0
}

# Locate binary
LILITH_BIN="${LILITH_ZERO_BIN:-$(command -v lilith-zero 2>/dev/null || true)}"
[ -z "$LILITH_BIN" ] && deny "lilith-zero binary not found — set LILITH_ZERO_BIN"
[[ "$LILITH_BIN" != /* ]] && deny "LILITH_ZERO_BIN must be an absolute path"
[ ! -x "$LILITH_BIN" ] && deny "lilith-zero not executable at: $LILITH_BIN"

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

# VS Code embeds hookEventName in the JSON — no --event flag needed
exec "$LILITH_BIN" hook \
    --format vscode \
    "${POLICY_ARGS[@]}" \
    "${AUDIT_ARGS[@]}"
