#!/usr/bin/env bash
# push-policy.sh — upload Cedar policy files to a running Lilith-Zero webhook server.
#
# Usage:
#   bash scripts/push-policy.sh                            # push all *.cedar files
#   bash scripts/push-policy.sh <agent-id>                 # push one agent's policy
#
# Config (from .env.lilith or environment):
#   LILITH_APP_URL    — base URL, e.g. https://lilith-zero.badcompany.xyz
#   LILITH_ADMIN_TOKEN — value of LILITH_ZERO_ADMIN_TOKEN set on the server
#
# Policy files are read from examples/copilot_studio/policies/ relative to repo root.

set -euo pipefail

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env.lilith"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

LILITH_APP_URL="${LILITH_APP_URL:?'Set LILITH_APP_URL in .env.lilith or environment'}"
LILITH_ADMIN_TOKEN="${LILITH_ADMIN_TOKEN:?'Set LILITH_ADMIN_TOKEN in .env.lilith or environment'}"

POLICY_DIR="$REPO_ROOT/examples/copilot_studio/policies"

if [[ ! -d "$POLICY_DIR" ]]; then
  echo "ERROR: policy directory not found: $POLICY_DIR" >&2
  exit 1
fi

UPLOAD_URL="${LILITH_APP_URL%/}/admin/upload-policy"

# ---------------------------------------------------------------------------
# Upload function
# ---------------------------------------------------------------------------

upload_policy() {
  local file="$1"
  local filename
  filename="$(basename "$file")"

  # Extract agent_id: strip leading "policy_" and trailing ".cedar"
  local agent_id="${filename%.cedar}"
  agent_id="${agent_id#policy_}"

  echo -n "  Uploading $filename (agent_id=$agent_id) ... "

  local http_code
  local response
  response=$(curl -sS -w "\n%{http_code}" \
    -X POST "${UPLOAD_URL}?agent_id=${agent_id}" \
    -H "X-Admin-Token: ${LILITH_ADMIN_TOKEN}" \
    -H "Content-Type: text/plain" \
    --data-binary "@${file}")

  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | head -n -1)

  if [[ "$http_code" == "200" ]]; then
    local reloaded elapsed
    reloaded=$(echo "$body" | grep -o '"reloaded":[0-9]*' | cut -d: -f2)
    elapsed=$(echo "$body" | grep -o '"elapsed_ms":[0-9]*' | cut -d: -f2)
    echo "OK (${reloaded} policies in memory, ${elapsed}ms)"
  else
    echo "FAILED (HTTP $http_code)"
    echo "  Response: $body" >&2
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if [[ $# -eq 1 ]]; then
  # Single agent ID supplied
  agent_id="$1"
  # Try both naming conventions
  file_prefixed="$POLICY_DIR/policy_${agent_id}.cedar"
  file_plain="$POLICY_DIR/${agent_id}.cedar"

  if [[ -f "$file_prefixed" ]]; then
    upload_policy "$file_prefixed"
  elif [[ -f "$file_plain" ]]; then
    upload_policy "$file_plain"
  else
    echo "ERROR: no policy file found for agent_id '$agent_id'" >&2
    echo "  Looked for: $file_prefixed" >&2
    echo "             $file_plain" >&2
    exit 1
  fi
else
  # Push all *.cedar files
  shopt -s nullglob
  files=("$POLICY_DIR"/*.cedar)

  if [[ ${#files[@]} -eq 0 ]]; then
    echo "No .cedar files found in $POLICY_DIR" >&2
    exit 1
  fi

  echo "Pushing ${#files[@]} policy file(s) to $LILITH_APP_URL"
  failed=0
  for f in "${files[@]}"; do
    upload_policy "$f" || ((failed++)) || true
  done

  if [[ $failed -gt 0 ]]; then
    echo "$failed upload(s) failed." >&2
    exit 1
  fi
  echo "All policies pushed successfully."
fi
