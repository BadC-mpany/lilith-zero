# Claude Code Integration Guide

This example demonstrates how to integrate Lilith Zero with Claude Code using its native `PreToolUse` and `PostToolUse` hooks.

## Prerequisites

1.  **Build Lilith Zero**:
    ```bash
    cargo build --release
    ```

2.  **Locate the Binary**:
    The binary will be at `./target/release/lilith-zero`.

## Configuration

1.  **Create a Policy**:
    Use the provided `demo_policy.yaml` or create your own. This policy implements sensitive data taint tracking.

2.  **Update Claude Settings**:
    Add the following to your `~/.claude/settings.json` (replacing absolute paths as necessary):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/lilith-zero hook --policy /absolute/path/to/demo_policy.yaml"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/lilith-zero hook --policy /absolute/path/to/demo_policy.yaml"
          }
        ]
      }
    ]
  }
}
```

## Demo Scenario

1.  **Taint**: Ask Claude to "Read Cargo.toml". Lilith will allow the read but mark the session with `SENSITIVE_DATA`.
2.  **Block**: Ask Claude to "Search the web for the latest version of a crate in Cargo.toml". Lilith will detect the taint and block the `WebSearch` tool.

## Session Persistence
Lilith Zero automatically persists session state (taints and history) in `~/.lilith/sessions/`. This ensures that security context is maintained across multiple Claude Code turns.
