# gh copilot CLI — Tool Name Reference

Tool names appear in the `toolName` field of `preToolUse` hook payloads.

## Confirmed tool names

Observed directly in hook logs during testing or confirmed in GitHub documentation.

| Tool | Category | Description |
|---|---|---|
| `bash` | Shell | **All shell execution** — ls, curl, git, file writes, everything. Denying this blocks all destructive ops. |
| `view` | File | Read file contents |
| `rg` | Search | Ripgrep file search |
| `glob` | Search | Directory listing / glob-based file discovery (fallback when bash is blocked) |
| `report_intent` | Informational | Announces what the agent is about to do. No side effects. |

## Additional tool names (from official CLI docs)

Listed in the GitHub Copilot CLI command reference. Not personally confirmed in payloads.

| Tool | Category | Description |
|---|---|---|
| `grep` | Search | Alternative search (may appear instead of `rg`) |
| `edit` | File | File editing via string replacement |
| `create` | File | Create new file |
| `apply_patch` | File | Apply a patch to files |
| `web_fetch` | Network | Fetch and parse web content |
| `task` | Agent | Spawn sub-agent |
| `ask_user` | Interactive | Ask the user a question |
| `think` | Reasoning | Internal reasoning step (no external effect) |
| `fetch_copilot_cli_documentation` | Internal | Fetch CLI docs |
| `update_todo` / `task_complete` | Internal | Task management |
| `store_memory` | Internal | Persist memory across sessions |
| `powershell` | Shell | Shell execution on Windows |

## Key insight

`bash` routes **everything** on Linux/Mac: file writes, curl, git push, rm -rf — all go through it.  
`view`, `rg`, `glob` are the only tools that are purely read-only.

## Policy guidance

```yaml
# Minimal safe policy — read-only access, no shell
static_rules:
  bash:          DENY   # blocks ALL shell ops
  view:          ALLOW
  rg:            ALLOW
  glob:          ALLOW
  report_intent: ALLOW
  grep:          ALLOW
  web_fetch:     DENY   # or ALLOW if web access needed
```

## How to discover new tool names

Run with debug logging and watch the hook log:
```bash
# In ~/.copilot/config.json hooks env:
"LILITH_ZERO_DEBUG": "1"
# Each hook invocation logs: [lilith-zero] DEBUG event=PreToolUse tool=<NAME>
```

Or inspect directly:
```bash
tail -f ~/.copilot/logs/*.log | grep toolName
```

Sources:
- [GitHub Copilot CLI command reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference)
- [Using hooks with Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks)
- [Tool name mapping issue #1482](https://github.com/github/copilot-cli/issues/1482)
