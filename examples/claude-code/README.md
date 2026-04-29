# Claude Code + Lilith Zero — Step-by-Step Setup

Intercept every tool call Claude Code makes with policy-as-code enforcement.
Lilith Zero reads the JSON event from stdin and signals via exit code: `0` = allow, `2` = block.

---

## 1. Install the Binary

Pick one method:

**Pre-built binary (macOS / Linux):**
```bash
curl -sSfL https://www.badcompany.xyz/lilith-zero/install.sh | sh
```

This installs to `~/.local/bin/lilith-zero`. If your shell doesn't find it afterward, add this to your `~/.zshrc` or `~/.bashrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload: `source ~/.zshrc`

**From source (requires Rust toolchain):**
```bash
git clone https://github.com/BadC-mpany/lilith-zero.git
cd lilith-zero
cargo install --path lilith-zero
```

**Verify:**
```bash
lilith-zero --version
```

---

## 2. Create a Policy File

Lilith Zero needs a YAML policy before it can enforce anything. Create one in your home directory (or wherever you prefer):

```bash
nano ~/policy.yaml
```

### Recommended: Bash Blocked (safe default)

This blocks shell access by default. Claude can still read, edit, and write files, use agents, browse the web — but the lethal trifecta engine will auto-block exfiltration if a session reads private data and then touches an untrusted source.

Copy the contents of [`policy-safe-default.yaml`](policy-safe-default.yaml) into your file.

### Alternative: Bash Enabled (explicit bypass)

If you need Claude to run shell commands, use [`policy-bash-enabled.yaml`](policy-bash-enabled.yaml) instead. Bash is allowed but NOT classified as EXFILTRATION, so the trifecta won't immediately fire after a web fetch. WebFetch/WebSearch are still tainted as `UNTRUSTED_SOURCE`.

> **Tip:** Keep both policies around. Point your hooks at `policy-safe-default.yaml` for normal work, swap to `policy-bash-enabled.yaml` when you need builds/tests.

---

## 3. Configure Claude Code Hooks

Create or edit your Claude Code settings. You can set this **per-project** (`.claude/settings.json` in the repo root) or **globally** (`~/.claude/settings.json`).

**Global (all projects):**
```bash
mkdir -p ~/.claude
cat > ~/.claude/settings.json << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "lilith-zero hook --policy ~/policy.yaml"
          }
        ]
      }
    ]
  }
}
EOF
```

**Per-project:**
```bash
mkdir -p .claude
cat > .claude/settings.json << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "lilith-zero hook --policy ~/policy.yaml"
          }
        ]
      }
    ]
  }
}
EOF
```

> **Note:** The `matcher` field is empty (`""`), which matches all tools. You can restrict it to specific tools if needed (e.g., `"Bash"` to only intercept shell commands).

---

## 4. Verify It Works

Start Claude Code and try the following:

**Should succeed** (Read is ALLOW in both policies):
```
Read the first 5 lines of README.md
```

**Should be blocked** (Bash is DENY in policy-safe-default.yaml):
```
Run ls in the terminal
```

You'll see Lilith's audit output on stderr. To see more detail, set `LILITH_ZERO_DEBUG=1`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "LILITH_ZERO_DEBUG=1 lilith-zero hook --policy ~/policy.yaml"
          }
        ]
      }
    ]
  }
}
```

---

## 5. Switching Policies

You don't need to rebuild anything to change policies — just point the hook at a different file:

| Policy | Bash | Lethal Trifecta | Use When |
| :--- | :--- | :--- | :--- |
| `policy-safe-default.yaml` | DENY | ON | Normal coding, code review, exploration |
| `policy-bash-enabled.yaml` | ALLOW | ON | Running builds, tests, cargo/npm commands |

To switch, edit the `--policy` path in your settings.json and restart Claude Code.

---

## Session Persistence

Lilith Zero persists taint state across tool calls within a session. State files live in `~/.lilith/sessions/`. If a `Read` tool call taints the session with `ACCESS_PRIVATE`, that taint is still active when the next tool call fires — even though each hook invocation is a separate process.

---

## Troubleshooting

**"command not found: lilith-zero"**
The binary is at `~/.local/bin/lilith-zero`. Make sure `~/.local/bin` is in your `$PATH`:
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

**"No such file: policy.yaml"**
The `--policy` path must point to an existing file. Use an absolute path (`~/policy.yaml`) or `$(pwd)/policy.yaml` if the file is always in the project root.

**All tools are blocked**
If no policy is loaded or the policy file has a parse error, Lilith fails closed (denies everything). Check:
```bash
lilith-zero hook --policy ~/policy.yaml --validate
```

**Hook isn't firing**
Make sure your `settings.json` is valid JSON and in the right location:
- Global: `~/.claude/settings.json`
- Project: `.claude/settings.json` (in the repo root)
