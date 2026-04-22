// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

//! OpenClaw hook adapter.
//!
//! Forward-looking implementation based on the proposed hook system tracked in
//! openclaw/openclaw#60943.  When that feature lands, update the field aliases
//! below to match the final schema.  Until then this adapter is wired in and
//! ready — it will activate automatically once OpenClaw emits hook payloads.
//!
//! # Format
//!
//! | Aspect      | OpenClaw (proposed)               |
//! |-------------|-----------------------------------|
//! | event name  | `event` or `hookEventName`        |
//! | tool name   | `toolName` or `tool_name`         |
//! | tool input  | `toolInput` or `tool_input`       |
//! | session key | `context.sessionId` or `sessionId`|
//! | allow       | exit code 0                       |
//! | deny        | exit code 2                       |
//!
//! # Integration (run mode — available today)
//!
//! Since OpenClaw supports stdio MCP only, wire lilith-zero via `run` mode:
//!
//! ```json
//! {
//!   "mcp": {
//!     "servers": {
//!       "my-server": {
//!         "command": "lilith-zero",
//!         "args": ["run", "--upstream-cmd", "npx -y @mcp/server",
//!                  "--policy", "/path/to/policy.yaml"],
//!         "transport": "stdio"
//!       }
//!     }
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};

/// Context block embedded in OpenClaw hook payloads.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct OpenClawContext {
    /// Session identifier scoped to this workspace.
    #[serde(rename = "sessionId", alias = "session_id", default)]
    pub session_id: Option<String>,
    /// Workspace identifier.
    #[serde(rename = "workspaceId", alias = "workspace_id", default)]
    pub workspace_id: Option<String>,
}

/// Hook payload sent by OpenClaw on stdin before any tool invocation.
///
/// Field names are accepted in both camelCase and snake_case to handle schema
/// evolution without breaking existing deployments.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OpenClawHookInput {
    /// Hook event type: `"preToolUse"` / `"postToolUse"` / `"sessionStart"` / `"sessionEnd"`.
    /// Also accepted as `hookEventName` (VS Code–style) for forward compat.
    #[serde(alias = "hookEventName", alias = "hook_event_name", default)]
    pub event: Option<String>,

    /// ISO-8601 timestamp of the event.
    #[serde(default)]
    pub timestamp: Option<String>,

    /// Absolute workspace path.
    #[serde(default)]
    pub cwd: Option<String>,

    /// Session and workspace identifiers.
    #[serde(default)]
    pub context: OpenClawContext,

    /// Session ID at the top level (fallback if `context.sessionId` is absent).
    #[serde(rename = "sessionId", alias = "session_id", default)]
    pub session_id: Option<String>,

    /// Tool being invoked (present for `preToolUse` / `postToolUse`).
    #[serde(rename = "toolName", alias = "tool_name", default)]
    pub tool_name: Option<String>,

    /// Tool arguments (present for `preToolUse`).
    #[serde(rename = "toolInput", alias = "tool_input", default)]
    pub tool_input: Option<serde_json::Value>,

    /// Tool output (present for `postToolUse`).
    #[serde(rename = "toolOutput", alias = "tool_output", default)]
    pub tool_output: Option<serde_json::Value>,

    /// Unique identifier for this tool invocation.
    #[serde(rename = "toolUseId", alias = "tool_use_id", default)]
    pub tool_use_id: Option<String>,
}

impl OpenClawHookInput {
    /// Resolve the effective session ID: `context.sessionId` → `sessionId` → hash of `cwd`.
    pub fn resolve_session_id(&self) -> String {
        self.context
            .session_id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.session_id.as_deref().filter(|s| !s.trim().is_empty()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                super::session::derive_session_id(self.cwd.as_deref().unwrap_or("openclaw-default"))
            })
    }

    /// Resolve the effective event name, normalizing to PascalCase.
    pub fn resolve_event(&self) -> &str {
        let raw = self.event.as_deref().unwrap_or_else(|| {
            if self.tool_output.is_some() {
                "postToolUse"
            } else if self.tool_name.is_some() {
                "preToolUse"
            } else {
                "SessionStart"
            }
        });
        normalize_event(raw)
    }

    /// Map to the internal [`super::HookInput`] format.
    pub fn to_hook_input(&self) -> super::HookInput {
        super::HookInput {
            session_id: self.resolve_session_id(),
            hook_event_name: self.resolve_event().to_string(),
            tool_name: self.tool_name.clone(),
            tool_input: self.tool_input.clone(),
            tool_output: self.tool_output.clone(),
            request_id: self.tool_use_id.clone(),
        }
    }
}

/// Normalize OpenClaw camelCase event names to the PascalCase used by `HookHandler`.
pub fn normalize_event(name: &str) -> &'static str {
    match name {
        "preToolUse" | "PreToolUse" | "pre_tool_use" => "PreToolUse",
        "postToolUse" | "PostToolUse" | "post_tool_use" => "PostToolUse",
        "sessionStart" | "SessionStart" | "session_start" => "SessionStart",
        "sessionEnd" | "SessionEnd" | "session_end" => "SessionEnd",
        _ => "PreToolUse",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_from_context() {
        let input: OpenClawHookInput = serde_json::from_str(
            r#"{"context":{"sessionId":"abc123"},"toolName":"read_file","toolInput":{}}"#,
        )
        .unwrap();
        assert_eq!(input.resolve_session_id(), "abc123");
    }

    #[test]
    fn test_session_id_fallback_to_top_level() {
        let input: OpenClawHookInput =
            serde_json::from_str(r#"{"sessionId":"top123","toolName":"read_file","toolInput":{}}"#)
                .unwrap();
        assert_eq!(input.resolve_session_id(), "top123");
    }

    #[test]
    fn test_event_inference_pre_tool() {
        let input: OpenClawHookInput =
            serde_json::from_str(r#"{"toolName":"read_file","toolInput":{}}"#).unwrap();
        assert_eq!(input.resolve_event(), "PreToolUse");
    }

    #[test]
    fn test_event_inference_post_tool() {
        let input: OpenClawHookInput =
            serde_json::from_str(r#"{"toolName":"read_file","toolOutput":"result"}"#).unwrap();
        assert_eq!(input.resolve_event(), "PostToolUse");
    }

    #[test]
    fn test_normalize_camel_case() {
        assert_eq!(normalize_event("preToolUse"), "PreToolUse");
        assert_eq!(normalize_event("postToolUse"), "PostToolUse");
        assert_eq!(normalize_event("sessionStart"), "SessionStart");
    }

    #[test]
    fn test_snake_case_aliases() {
        let input: OpenClawHookInput = serde_json::from_str(
            r#"{"hook_event_name":"preToolUse","tool_name":"bash","tool_input":{"cmd":"ls"}}"#,
        )
        .unwrap();
        assert_eq!(input.resolve_event(), "PreToolUse");
        assert_eq!(input.tool_name.as_deref(), Some("bash"));
    }
}
