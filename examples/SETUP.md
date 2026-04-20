# Lilith Zero — Hook Integration Setup

Secure your AI coding agents by intercepting every tool call with policy-as-code enforcement.

## Prerequisites

Build the binary from the repo root:

```bash
cd lilith-zero
cargo build
```

The binary is at `lilith-zero/target/debug/lilith-zero`. The wrapper scripts auto-discover it — no `PATH` changes needed if you run hooks from within this repo.

---

## gh copilot CLI

### What gets intercepted
Every tool call `gh copilot` makes: `bash` (shell commands, file writes, curl, git), `view` (file reads), `rg` (search), `glob` (directory listing).

### Configure

**Option A — Global (all sessions on your machine)**

Add to `~/.copilot/config.json`:

```json
{
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "bash": "/absolute/path/to/lilith-zero/examples/gh-copilot/hook-wrapper.sh",
        "env": { "LILITH_ZERO_EVENT": "preToolUse" },
        "timeoutSec": 10
      }
    ],
    "postToolUse": [
      {
        "type": "command",
        "bash": "/absolute/path/to/lilith-zero/examples/gh-copilot/hook-wrapper.sh",
        "env": { "LILITH_ZERO_EVENT": "postToolUse" },
        "timeoutSec": 10
      }
    ]
  }
}
```

**Option B — Repo-level**

Copy `examples/gh-copilot/hooks.json` to `.github/hooks/hooks.json` in the repo you want to protect. `gh copilot` loads it automatically from the git root.

### Policy file

Default: `examples/gh-copilot/policy-static.yaml` (auto-discovered).
To override: set `LILITH_ZERO_POLICY=/absolute/path/to/policy.yaml` in the env block.

### Test

```bash
# Should be BLOCKED (bash is DENY in policy-static.yaml)
gh copilot -- -p "run ls" --allow-all-tools

# Should be ALLOWED (view is ALLOW)
gh copilot -- -p "show me the first 5 lines of Cargo.toml" --allow-all-tools
```

---

## VS Code Copilot (sidebar agent mode)

### What gets intercepted
Every tool call in agent mode: `read_file`, `create_file`, `insert_edit_into_file`, `run_in_terminal`, `fetch`, and all MCP tools.

### Configure

**Step 1** — VS Code settings (`Ctrl+,` → Open Settings JSON):

```json
{
  "chat.useCustomAgentHooks": true,
  "chat.hookFilesLocations": [
    "/absolute/path/to/lilith-zero/examples/vscode/hooks.json"
  ]
}
```

Replace the path with the actual absolute path on your machine.

**Step 2** — No further configuration needed. The wrapper auto-discovers the binary and policy.

### Policy file

Default: `examples/vscode/policy-static.yaml` (auto-discovered).
To override: set `LILITH_ZERO_POLICY` in the `env` block of `examples/vscode/hooks.json`.

### Test

In VS Code Copilot chat → **agent mode**:

```
show me the first 5 lines of README.md
```
→ Should succeed (read_file is ALLOW).

```
run ls in the terminal
```
→ Should be blocked (run_in_terminal is DENY).

---

## Debug mode

Add `"LILITH_ZERO_DEBUG": "1"` to any hook's `env` block to see exactly what's happening:

```json
"env": {
  "LILITH_ZERO_EVENT": "PreToolUse",
  "LILITH_ZERO_POLICY": "examples/vscode/policy-static.yaml",
  "LILITH_ZERO_DEBUG": "1"
}
```

VS Code: check **Output → GitHub Copilot** panel.  
gh copilot CLI: debug lines appear on stderr in your terminal.

---

## Policies

| File | Description |
|---|---|
| `policy-static.yaml` | Fixed allow/deny by tool name. Start here. |
| `policy-taint.yaml` | Blocks network calls after any file read (exfiltration prevention). |
| `policy-lethal-trifecta.yaml` | Auto-blocks exfiltration when both private-data and untrusted-source taints are active. |

Edit the policy and restart the agent — no rebuild needed.
