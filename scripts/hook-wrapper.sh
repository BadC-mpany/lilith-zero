#!/bin/bash
# Lilith Zero — GitHub Copilot hook wrapper (Linux / macOS / CodeBox)
#
# PURPOSE
#   This script is the entry point configured in .github/hooks/hooks.json
#   for every Copilot hook event. It locates the lilith-zero binary, validates
#   the path, and forwards stdin to the security engine.
#
# SECURITY DESIGN
#   - Fail-closed: if the binary is not found or its path is not absolute,
#     we write a deny decision to stdout and exit 0. We never allow by default.
#   - No eval / no dynamic command construction from environment input.
#   - Binary path must be absolute to prevent workspace files from shadowing it.
#   - The LILITH_ZERO_POLICY path is not executed — it is passed only as a flag.
#
# CONFIGURATION (via environment variables)
#   LILITH_ZERO_BIN      Absolute path to the lilith-zero binary.
#                        Default: first `lilith-zero` found on $PATH.
#   LILITH_ZERO_POLICY   Absolute path to the policy YAML file.
#                        Default: .github/hooks/lilith-policy.yaml in the repo root.
#   LILITH_ZERO_EVENT    Copilot event name (preToolUse | postToolUse | sessionStart | sessionEnd).
#                        Must be set when Copilot cannot pass --event directly.
#                        Typically configured via the `env` field in hooks.json.
#   LILITH_ZERO_AUDIT    Path for the audit log file. Optional.
#
# USAGE (in .github/hooks/hooks.json)
#   {
#     "version": 1,
#     "hooks": {
#       "preToolUse": [{
#         "type": "command",
#         "bash": ".github/hooks/hook-wrapper.sh",
#         "env": { "LILITH_ZERO_EVENT": "preToolUse" },
#         "timeoutSec": 10
#       }],
#       "postToolUse": [{
#         "type": "command",
#         "bash": ".github/hooks/hook-wrapper.sh",
#         "env": { "LILITH_ZERO_EVENT": "postToolUse" },
#         "timeoutSec": 10
#       }]
#     }
#   }
#
# INSTALLATION
#   Copy this script to .github/hooks/hook-wrapper.sh in your repository.
#   Set it as executable: chmod +x .github/hooks/hook-wrapper.sh
#   Ensure LILITH_ZERO_BIN or lilith-zero on PATH points to a trusted binary.

set -euo pipefail

# ---------------------------------------------------------------------------
# Fail-closed helper: write a deny JSON to stdout and exit 0.
# We always exit 0 because Copilot reads the JSON, not the exit code.
# ---------------------------------------------------------------------------
deny() {
    local reason="${1:-unknown error}"
    # Escape the reason string for JSON (basic escaping; no eval involved)
    local escaped
    escaped=$(printf '%s' "$reason" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g')
    printf '{"permissionDecision":"deny","permissionDecisionReason":"%s"}\n' "$escaped"
    exit 0
}

# ---------------------------------------------------------------------------
# Locate the lilith-zero binary
# ---------------------------------------------------------------------------
LILITH_BIN="${LILITH_ZERO_BIN:-}"

if [ -z "$LILITH_BIN" ]; then
    LILITH_BIN="$(command -v lilith-zero 2>/dev/null || true)"
fi

if [ -z "$LILITH_BIN" ]; then
    deny "lilith-zero binary not found: set LILITH_ZERO_BIN or add it to PATH"
fi

# ---------------------------------------------------------------------------
# Security: require absolute path to prevent workspace file shadowing.
# A relative path could resolve to an attacker-controlled file in the cwd.
# ---------------------------------------------------------------------------
if [[ "$LILITH_BIN" != /* ]]; then
    deny "LILITH_ZERO_BIN must be an absolute path, got: $LILITH_BIN"
fi

if [ ! -x "$LILITH_BIN" ]; then
    deny "lilith-zero binary not executable at: $LILITH_BIN"
fi

# ---------------------------------------------------------------------------
# Resolve output format and event name
#
# LILITH_ZERO_FORMAT selects the hook protocol:
#   copilot  — GitHub Copilot CLI / cloud coding agent (camelCase events, flat JSON output)
#   vscode   — VS Code Copilot sidebar agent mode (PascalCase events, hookSpecificOutput)
#
# For vscode format, LILITH_ZERO_EVENT is optional: VS Code embeds the event
# name in the JSON payload as hookEventName. For copilot format, the event
# must be supplied explicitly.
# ---------------------------------------------------------------------------
FORMAT="${LILITH_ZERO_FORMAT:-copilot}"

case "$FORMAT" in
    copilot|vscode) ;;
    *) deny "Invalid LILITH_ZERO_FORMAT value: $FORMAT (must be copilot or vscode)" ;;
esac

EVENT="${LILITH_ZERO_EVENT:-}"
EVENT_ARGS=()

if [ "$FORMAT" = "copilot" ]; then
    # Copilot CLI/cloud: event must be explicit (not embedded in JSON)
    if [ -z "$EVENT" ]; then
        deny "LILITH_ZERO_EVENT must be set for --format copilot (e.g. preToolUse, postToolUse)"
    fi
    # Allowlist camelCase event names
    case "$EVENT" in
        preToolUse|postToolUse|sessionStart|sessionEnd|userPromptSubmitted|errorOccurred) ;;
        *) deny "Invalid LILITH_ZERO_EVENT value: $EVENT" ;;
    esac
    EVENT_ARGS=(--event "$EVENT")
elif [ -n "$EVENT" ]; then
    # VS Code: event is optional (embedded in JSON) but can be overridden
    # Allowlist PascalCase event names
    case "$EVENT" in
        PreToolUse|PostToolUse|SessionStart|SessionEnd|UserPromptSubmit|SubagentStart|SubagentStop|Stop|PreCompact) ;;
        *) deny "Invalid LILITH_ZERO_EVENT value: $EVENT" ;;
    esac
    EVENT_ARGS=(--event "$EVENT")
fi

# ---------------------------------------------------------------------------
# Resolve policy file (optional but strongly recommended)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd 2>/dev/null || echo "$SCRIPT_DIR")"

POLICY="${LILITH_ZERO_POLICY:-$REPO_ROOT/.github/hooks/lilith-policy.yaml}"

POLICY_ARGS=()
if [ -n "$POLICY" ] && [ -f "$POLICY" ]; then
    # Validate absolute path for policy too
    if [[ "$POLICY" != /* ]]; then
        deny "LILITH_ZERO_POLICY must be an absolute path"
    fi
    POLICY_ARGS=(--policy "$POLICY")
fi

# ---------------------------------------------------------------------------
# Resolve optional audit log path
# ---------------------------------------------------------------------------
AUDIT_ARGS=()
if [ -n "${LILITH_ZERO_AUDIT:-}" ]; then
    AUDIT_ARGS=(--audit-logs "$LILITH_ZERO_AUDIT")
fi

# ---------------------------------------------------------------------------
# Forward stdin to lilith-zero
# Stdin is passed through automatically because we use exec.
# ---------------------------------------------------------------------------
exec "$LILITH_BIN" hook \
    --format "$FORMAT" \
    "${EVENT_ARGS[@]}" \
    "${POLICY_ARGS[@]}" \
    "${AUDIT_ARGS[@]}"
