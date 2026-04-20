#!/bin/bash
# Lilith Zero — one-command setup for VS Code and gh copilot hooks
#
# Run from the REPO ROOT:
#   cd /path/to/lilith-zero
#   bash setup-hooks.sh

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { printf "${GREEN}✓${NC}  %s\n" "$*"; }
warn() { printf "${YELLOW}!${NC}  %s\n" "$*"; }

REPO_ROOT="$(pwd)"
CRATE_DIR="$REPO_ROOT/lilith-zero"
BIN_DIR="$HOME/.local/bin"
HOOKS_DIR="$REPO_ROOT/.github/hooks"

echo ""; echo "━━━ Lilith Zero Hook Setup ━━━"; echo ""

# 1. Build
echo "Step 1/4  Build"
if ! (cd "$CRATE_DIR" && cargo build 2>&1 | grep -E "^(   Compiling|    Finished|error)"); then
    echo "Build failed"; exit 1
fi
BINARY="$CRATE_DIR/target/debug/lilith-zero"
[ ! -x "$BINARY" ] && { echo "Build produced no binary"; exit 1; }
ok "Built: $BINARY"

# 2. Install to PATH
echo ""; echo "Step 2/4  Install to ~/.local/bin"
mkdir -p "$BIN_DIR"
cp "$BINARY" "$BIN_DIR/lilith-zero"
chmod +x "$BIN_DIR/lilith-zero"
ok "Installed: $BIN_DIR/lilith-zero"
if ! echo "$PATH" | grep -q "$BIN_DIR"; then
    warn "Add to your shell profile: export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# 3. .github/hooks/
echo ""; echo "Step 3/4  .github/hooks/"
mkdir -p "$HOOKS_DIR"
cp "$REPO_ROOT/examples/gh-copilot/hook-wrapper.sh" "$HOOKS_DIR/hook-wrapper.sh"
chmod +x "$HOOKS_DIR/hook-wrapper.sh"
ok "Wrapper copied to .github/hooks/hook-wrapper.sh"

POLICY_DEST="$HOOKS_DIR/lilith-policy.yaml"
if [ -f "$POLICY_DEST" ]; then
    ok "Policy exists (kept): .github/hooks/lilith-policy.yaml"
else
    cp "$REPO_ROOT/examples/gh-copilot/policy-static.yaml" "$POLICY_DEST"
    ok "Default policy created: .github/hooks/lilith-policy.yaml"
fi

# 4. Print VS Code snippet
echo ""; echo "Step 4/4  VS Code"
echo ""
echo "Paste into VS Code settings (Cmd/Ctrl+, → Open JSON):"
echo ""
cat << EOF
{
  "chat.useCustomAgentHooks": true,
  "chat.hookFilesLocations": [
    "\${workspaceFolder}/examples/vscode/hooks.json"
  ]
}
EOF
echo ""

# Optionally create .vscode/settings.json
VSCODE_SETTINGS="$REPO_ROOT/.vscode/settings.json"
if [ ! -f "$VSCODE_SETTINGS" ]; then
    read -rp "Create .vscode/settings.json now? [y/N] " yn
    if [[ "${yn:-n}" =~ ^[Yy]$ ]]; then
        mkdir -p "$REPO_ROOT/.vscode"
        printf '{\n  "chat.useCustomAgentHooks": true,\n  "chat.hookFilesLocations": [\n    "${workspaceFolder}/examples/vscode/hooks.json"\n  ]\n}\n' > "$VSCODE_SETTINGS"
        ok "Created .vscode/settings.json"
    fi
else
    warn ".vscode/settings.json already exists — merge manually if needed"
fi

# Optionally update ~/.copilot/config.json
COPILOT_CONFIG="$HOME/.copilot/config.json"
if [ -f "$COPILOT_CONFIG" ]; then
    echo ""
    read -rp "Update ~/.copilot/config.json for gh copilot CLI? [y/N] " yn
    if [[ "${yn:-n}" =~ ^[Yy]$ ]]; then
        cp "$COPILOT_CONFIG" "${COPILOT_CONFIG}.bak"
        python3 - <<PYEOF
import json
with open("$COPILOT_CONFIG") as f: config = json.load(f)
w = "$HOOKS_DIR/hook-wrapper.sh"
p = "$POLICY_DEST"
h = lambda ev: {"type":"command","bash":w,"env":{"LILITH_ZERO_EVENT":ev,"LILITH_ZERO_POLICY":p},"timeoutSec":10}
config["hooks"] = {"preToolUse":[h("preToolUse")],"postToolUse":[h("postToolUse")]}
with open("$COPILOT_CONFIG","w") as f: json.dump(config,f,indent=2)
PYEOF
        ok "Updated ~/.copilot/config.json (backup at .bak)"
    fi
fi

echo ""
echo "━━━ Done ━━━"
echo ""
echo "Policy:  $POLICY_DEST"
echo "Edit it to customise your security rules."
echo ""
echo "Test: gh copilot -- -p 'run ls' --allow-all-tools"
echo "  → Should show: ✗ Denied by preToolUse hook"
echo ""
