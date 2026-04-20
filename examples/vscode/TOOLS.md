# VS Code Copilot Sidebar — Tool Name Reference

Tool names appear in the `tool_name` field of `PreToolUse` hook payloads.

**Important:** VS Code sends ALL hook fields in snake_case (`tool_name`, `hook_event_name`,
`session_id`) — NOT camelCase as the spec/docs suggest. The policy engine matches on
the exact value in `tool_name`.

## Confirmed tool names

Observed directly in VS Code hook logs during live testing.

| Tool | Category | Description |
|---|---|---|
| `read_file` | File | Read file contents |
| `insert_edit_into_file` | File | Edit/patch an existing file |
| `create_file` | File | Create a new file |
| `edit_file` | File | Alternative edit tool (confirmed in VS Code issues) |
| `run_in_terminal` | Shell | Execute a terminal command |
| `fetch_webpage` | Network | Fetch and parse a web URL |
| `find_files` | Search | Find files by name/pattern |
| `search` | Search | Text search across workspace |
| `get_errors` | Diagnostics | Get linter/compiler errors |
| `get_changed_files` | Git | List files changed in working tree |

## Additional tool names (from VS Code docs / source)

Not yet personally confirmed in payloads but documented or referenced.

| Tool | Category | Description |
|---|---|---|
| `delete_file` | File | Delete a file |
| `run_vs_code_task` | Shell | Run a configured VS Code task |
| `run_git_command` | Git | Execute a git command |
| `push_to_github` | Git | Push commits to GitHub |
| `create_directory` | File | Create a directory |
| `list_directory` | File | List directory contents |
| `semantic_search` | Search | Semantic/AI-powered code search |
| `grep_search` | Search | Grep-style regex search |
| `file_search` | Search | Alternative file search |
| `get_diagnostics` | Diagnostics | Get VS Code diagnostics |
| `browser_action` | Browser | Interact with integrated browser (experimental) |
| `mcp_*` | MCP | Any tool from a configured MCP server |

## Key differences from gh copilot CLI

| | VS Code | gh copilot CLI |
|---|---|---|
| Tool names | Long snake_case (`read_file`, `run_in_terminal`) | Short (`bash`, `view`, `rg`) |
| Shell execution | `run_in_terminal` | `bash` |
| File read | `read_file` | `view` |
| File search | `search`, `find_files` | `rg`, `glob` |
| Web fetch | `fetch_webpage` | `web_fetch` |
| **Granularity** | Separate tool per operation | `bash` covers everything |

VS Code tools are more granular — you can allow `read_file` while denying `run_in_terminal`.  
In gh copilot CLI, all destructive ops go through a single `bash` tool.

## Policy guidance

```yaml
# Taint tracking: read → blocks web fetch
taint_rules:
  - tool: read_file
    action: ADD_TAINT
    tag: SENSITIVE_DATA
  - tool: fetch_webpage
    action: CHECK_TAINT
    required_taints: ["SENSITIVE_DATA"]
    error: "blocked: web fetch after file read"
```

## How to discover new tool names

Enable debug in `examples/vscode/hooks.json`:
```json
"LILITH_ZERO_DEBUG": "1"
```
Then check **VS Code Output → GitHub Copilot** panel. Every hook invocation logs:
```
[lilith-zero] DEBUG event=PreToolUse tool=<EXACT_NAME> session=...
[lilith-zero] DEBUG stdin: {"tool_name":"<EXACT_NAME>", ...}
```

Any tool producing `permissionDecision=deny` for something you expect to be allowed = new
tool name to add to the policy.

Sources:
- [VS Code Agent Hooks (Preview)](https://code.visualstudio.com/docs/copilot/customization/hooks)
- [VS Code Agent Tools](https://code.visualstudio.com/docs/copilot/agents/agent-tools)
- [copilot-cli issue #1482 — tool name mapping](https://github.com/github/copilot-cli/issues/1482)
- [VS Code issue #253561 — agent tool access](https://github.com/microsoft/vscode/issues/253561)
