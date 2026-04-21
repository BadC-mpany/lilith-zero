#!/bin/bash
# Universal Lilith Zero — "Banger Demo" Security Dashboard
# Self-Resolving Logic: Works from any directory (Repo root or Workspace root)

set -euo pipefail

# ANSI Color Codes
CYAN='\033[1;36m'
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[1;35m'
BLUE='\033[1;34m'
GRAY='\033[0;90m'
NC='\033[0m' 
BOLD='\033[1m'

# 1. Self-Location Resolution
# This ensures we find the policy and logs even if the IDE CWD is different.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Absolute paths for stability
LOG_FILE="$SCRIPT_DIR/lilith-live.log"
AUDIT_LOG="/tmp/lilith-audit.log"
LOCK_FILE="/tmp/lilith-dashboard.lock"
DEFAULT_POLICY="$SCRIPT_DIR/policy-banger.yaml"

# Locate Binary
LILITH_BIN="$HOME/.local/bin/lilith-zero"
[ ! -x "$LILITH_BIN" ] && LILITH_BIN="$GIT_ROOT/lilith-zero/target/release/lilith-zero"
[ ! -x "$LILITH_BIN" ] && LILITH_BIN="$GIT_ROOT/lilith-zero/target/debug/lilith-zero"

# Final Policy Decision
POLICY="${LILITH_ZERO_POLICY:-$DEFAULT_POLICY}"

# 2. Read input
INPUT_JSON=$(cat)

# 3. Format Detection
FORMAT="${LILITH_ZERO_FORMAT:-}"
if [ -z "$FORMAT" ]; then
    if echo "$INPUT_JSON" | grep -q '"tool_name"'; then
        FORMAT="vscode"
    elif echo "$INPUT_JSON" | grep -q '"toolName"'; then
        FORMAT="copilot"
    elif echo "$INPUT_JSON" | grep -q '"hook_event_name"'; then
        FORMAT="claude"
    else
        FORMAT="vscode"
    fi
fi

# 4. Extract Meta
case "$FORMAT" in
    vscode|claude)
        TOOL_NAME=$(echo "$INPUT_JSON" | grep -oP '"tool_name":"\K[^"]+' || echo "unknown")
        TOOL_ARGS=$(echo "$INPUT_JSON" | grep -oP '"tool_input":\K\{.*?\}' || echo "")
        EVENT_NAME=$(echo "$INPUT_JSON" | grep -oP '"hook_event_name":"\K[^"]+' || echo "PreToolUse")
        SESSION_ID=$(echo "$INPUT_JSON" | grep -oP '"session_id":"\K[^"]+' | head -n 1 || echo "default")
        ;;
    copilot)
        TOOL_NAME=$(echo "$INPUT_JSON" | grep -oP '"toolName":"\K[^"]+' || echo "unknown")
        TOOL_ARGS=$(echo "$INPUT_JSON" | grep -oP '"toolArgs":\K\{.*?\}' || echo "")
        EVENT_NAME=$(echo "$INPUT_JSON" | grep -oP '"event":"\K[^"]+' || echo "${LILITH_ZERO_EVENT:-preToolUse}")
        SESSION_ID=$(echo "$INPUT_JSON" | grep -oP '"sessionID":"\K[^"]+' | head -n 1 || echo "default")
        [[ "$EVENT_NAME" == "preToolUse" ]] && EVENT_NAME="PreToolUse"
        [[ "$EVENT_NAME" == "postToolUse" ]] && EVENT_NAME="PostToolUse"
        ;;
esac

TIME_STAMP=$(date +'%H:%M:%S')
SHORT_SESSION="${SESSION_ID:0:8}"

# 4. Call Lilith
# Note: If Lilith fails, we force a DENY for VS Code/Copilot to be fail-closed.
if ! OUT_JSON=$(echo "$INPUT_JSON" | "$LILITH_BIN" hook --format "$FORMAT" --policy "$POLICY" --audit-logs "$AUDIT_LOG" --event "$EVENT_NAME" 2>/dev/null); then
    if [ "$FORMAT" == "vscode" ]; then
        OUT_JSON="{\"hookSpecificOutput\":{\"hookEventName\":\"$EVENT_NAME\",\"permissionDecision\":\"deny\"}}"
    elif [ "$FORMAT" == "copilot" ]; then
        OUT_JSON="{\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"Lilith Binary Error\"}"
    else
        exit 2
    fi
fi
DECISION=$(echo "$OUT_JSON" | grep -oP '"permissionDecision":"\K[^"]+' || echo "deny")

# 6. Dashboard Output (Atomic locked writes to absolute $LOG_FILE)
(
    flock -x 200
    if [[ "$EVENT_NAME" == "PreToolUse" ]]; then
        msg="${GRAY}────────────────────────────────────────────────────────────────────────────────${NC}\n"
        msg="${msg}  ${CYAN}ACTION:${NC}  %-13s  ${CYAN}SESSION:${NC} ${GRAY}%s...${NC}  ${CYAN}INT:${NC} ${BLUE}%s${NC}\n"
        
        if [ "$DECISION" == "deny" ]; then
            msg="${msg}  ${CYAN}TOOL:${NC}    ${BOLD}%s${NC} ${GRAY}%s${NC}\n"
            msg="${msg}  ${BOLD}${RED}STATUS:  BLOCKED${NC}         ${GRAY}[%s]${NC}\n"
            msg="${msg}  ${YELLOW}REASON:  Lethal Trifecta (Sensitive Data + Untrusted Source)${NC}\n"
        else
            msg="${msg}  ${CYAN}TOOL:${NC}    ${BOLD}%s${NC}\n"
            msg="${msg}  ${GREEN}STATUS:  AUTHORIZED${NC}      ${GRAY}[%s]${NC}\n"
        fi
        msg="${msg}${GRAY}────────────────────────────────────────────────────────────────────────────────${NC}\n"
        
        if [ "$DECISION" == "deny" ]; then
            printf "$msg" "$EVENT_NAME" "$SHORT_SESSION" "$FORMAT" "$TOOL_NAME" "$TOOL_ARGS" "$TIME_STAMP" >> "$LOG_FILE"
        else
            printf "$msg" "$EVENT_NAME" "$SHORT_SESSION" "$FORMAT" "$TOOL_NAME" "$TIME_STAMP" >> "$LOG_FILE"
        fi
        echo "" >> "$LOG_FILE"
        
    elif [[ "$EVENT_NAME" == "PostToolUse" ]]; then
        LOCAL_TAINT=$(tail -n 40 "$AUDIT_LOG" 2>/dev/null | grep "$SESSION_ID" | grep '"event_type":"TaintAdded"' | tail -n 1 || true)
        if [ -n "$LOCAL_TAINT" ]; then
            TAINT_TAG=$(echo "$LOCAL_TAINT" | grep -oP '"tag":"\K[^"]+')
            printf "  ${GRAY}[%s]${NC}  ${BOLD}${MAGENTA}ALERT:${NC} Context tracked as ${BOLD}[%s]${NC} via %s\n\n" "$TIME_STAMP" "$TAINT_TAG" "$TOOL_NAME" >> "$LOG_FILE"
        fi
    fi
) 200>"$LOCK_FILE"

# 7. Exit Signaling
if [ "$FORMAT" == "claude" ]; then
    [ "$DECISION" == "deny" ] && exit 2
    exit 0
else
    echo "$OUT_JSON"
fi
