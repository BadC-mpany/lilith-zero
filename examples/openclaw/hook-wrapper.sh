#!/bin/bash
# Lilith Zero — OpenClaw hook wrapper (forward-looking)
#
# This script will be used once OpenClaw ships its pre/post tool hook system
# (tracked in openclaw/openclaw#60943). Until then, use `lilith-zero run`
# mode to wrap MCP server stdio connections (see openclaw.json).
#
# ENV VARS (all optional):
#   LILITH_ZERO_BIN      Override binary path (absolute).
#   LILITH_ZERO_POLICY   Override policy file path.
#   LILITH_ZERO_AUDIT    Path for audit log output.
#   LILITH_ZERO_DEBUG    Set to "1" for debug output on stderr.

set -euo pipefail

DEBUG="${LILITH_ZERO_DEBUG:-0}"
log_debug() { [ "$DEBUG" = "1" ] && printf '[lilith-zero] %s\n' "$*" >&2 || true; }

deny() {
    local reason="${1:-internal error}"
    local escaped; escaped=$(printf '%s' "$reason" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '{"decision":"deny","reason":"%s"}\n' "$escaped"
    exit 0
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_ROOT="$(cd "$SCRIPT_DIR" && git rev-parse --show-toplevel 2>/dev/null || (cd "$SCRIPT_DIR/../.." && pwd))"

LILITH_BIN="${LILITH_ZERO_BIN:-}"
[ -z "$LILITH_BIN" ] && LILITH_BIN="$(command -v lilith-zero 2>/dev/null || true)"
if [ -z "$LILITH_BIN" ] || [ ! -x "$LILITH_BIN" ]; then
    for c in \
        "$HOME/.local/bin/lilith-zero" \
        "$GIT_ROOT/lilith-zero/target/debug/lilith-zero" \
        "$GIT_ROOT/lilith-zero/target/release/lilith-zero"; do
        [ -x "$c" ] && { LILITH_BIN="$c"; break; }
    done
fi
[ -z "$LILITH_BIN" ] || [ ! -x "$LILITH_BIN" ] && deny "binary not found — run: cd lilith-zero && cargo build"

POLICY="${LILITH_ZERO_POLICY:-}"
if [ -z "$POLICY" ] || [ ! -f "$POLICY" ]; then
    for c in \
        "$GIT_ROOT/.github/hooks/lilith-policy.yaml" \
        "$SCRIPT_DIR/policy-base.yaml"; do
        [ -f "$c" ] && { POLICY="$c"; break; }
    done
fi
POLICY_ARGS=()
[ -n "$POLICY" ] && [ -f "$POLICY" ] && POLICY_ARGS=(--policy "$POLICY")

AUDIT_ARGS=()
[ -n "${LILITH_ZERO_AUDIT:-}" ] && AUDIT_ARGS=(--audit-logs "$LILITH_ZERO_AUDIT")

log_debug "binary: $LILITH_BIN"
log_debug "policy: ${POLICY:-<none>}"

exec "$LILITH_BIN" hook --format openclaw "${POLICY_ARGS[@]}" "${AUDIT_ARGS[@]}"
