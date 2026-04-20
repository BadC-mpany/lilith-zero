#!/bin/bash
# Lilith Zero — VS Code Copilot sidebar hook wrapper
#
# Called by VS Code for every tool event (PreToolUse, PostToolUse, SessionStart, …).
# Self-discovers the binary and policy — zero configuration needed if you built
# with `cargo build` from the repo root or installed to ~/.local/bin.
#
# ENV VARS (all optional):
#   LILITH_ZERO_BIN      Override binary path (absolute).
#   LILITH_ZERO_POLICY   Override policy file path.
#   LILITH_ZERO_EVENT    Event name fallback (VS Code Preview sometimes omits hookEventName).
#   LILITH_ZERO_AUDIT    Path for audit log output.
#   LILITH_ZERO_DEBUG    Set to "1" to print debug info to stderr.
#
# VISIBILITY: add "LILITH_ZERO_DEBUG": "1" to the hooks.json env block,
# then check VS Code Output panel → GitHub Copilot Hooks.

set -euo pipefail

DEBUG="${LILITH_ZERO_DEBUG:-0}"
log_debug() { [ "$DEBUG" = "1" ] && printf '[lilith-zero] %s\n' "$*" >&2 || true; }

deny() {
    local reason="${1:-internal error}"
    local escaped; escaped=$(printf '%s' "$reason" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$escaped"
    exit 0
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_ROOT="$(cd "$SCRIPT_DIR" && git rev-parse --show-toplevel 2>/dev/null || echo "$SCRIPT_DIR/../..")"

# --- Find binary ---
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
[ -z "$LILITH_BIN" ] || [ ! -x "$LILITH_BIN" ] && \
    deny "binary not found — run: cd lilith-zero && cargo build"
[[ "$LILITH_BIN" != /* ]] && deny "LILITH_ZERO_BIN must be absolute"

# --- Find policy ---
POLICY="${LILITH_ZERO_POLICY:-}"
if [ -z "$POLICY" ] || [ ! -f "$POLICY" ]; then
    for c in \
        "$GIT_ROOT/.github/hooks/lilith-policy.yaml" \
        "$SCRIPT_DIR/policy-static.yaml"; do
        [ -f "$c" ] && { POLICY="$c"; break; }
    done
fi
POLICY_ARGS=()
[ -n "$POLICY" ] && [ -f "$POLICY" ] && POLICY_ARGS=(--policy "$POLICY")

# --- Event (belt-and-suspenders: VS Code Preview omits hookEventName from payload) ---
EVENT_ARGS=()
if [ -n "${LILITH_ZERO_EVENT:-}" ]; then
    case "$LILITH_ZERO_EVENT" in
        PreToolUse|PostToolUse|SessionStart|SessionEnd|UserPromptSubmit|SubagentStart|SubagentStop|Stop|PreCompact) ;;
        *) LILITH_ZERO_EVENT="PreToolUse" ;;
    esac
    EVENT_ARGS=(--event "$LILITH_ZERO_EVENT")
fi

AUDIT_ARGS=()
[ -n "${LILITH_ZERO_AUDIT:-}" ] && AUDIT_ARGS=(--audit-logs "$LILITH_ZERO_AUDIT")

log_debug "binary:   $LILITH_BIN"
log_debug "policy:   ${POLICY:-<none — fail-closed>}"
log_debug "event:    ${LILITH_ZERO_EVENT:-<from payload>}"
log_debug "git-root: $GIT_ROOT"

exec "$LILITH_BIN" hook --format vscode "${EVENT_ARGS[@]}" "${POLICY_ARGS[@]}" "${AUDIT_ARGS[@]}"
