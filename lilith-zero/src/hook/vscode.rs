// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

//! VS Code Copilot sidebar agent hook adapter.
//!
//! Handles the hook format used by the VS Code Copilot sidebar agent ("agent mode")
//! when the user opens the chat panel, activates agent mode, and the LLM begins
//! invoking tools such as `editFiles`, `runTerminalCommand`, `#fetch`, MCP tools, etc.
//!
//! # Format differences from other adapters
//!
//! | Aspect        | Claude Code          | Copilot CLI/Cloud     | VS Code Sidebar       |
//! |---------------|----------------------|-----------------------|-----------------------|
//! | session key   | `session_id`         | derived from `cwd`    | `sessionId`           |
//! | event name    | `hook_event_name`    | `--event` flag        | `hookEventName`       |
//! | tool name     | `tool_name`          | `toolName`            | `tool_name`           |
//! | tool args     | `tool_input`         | `toolArgs` (string)   | `tool_input`          |
//! | allow signal  | exit 0               | `permissionDecision`  | `hookSpecificOutput`  |
//! | deny signal   | exit 2               | `permissionDecision`  | `hookSpecificOutput`  |
//! | hooks.json    | `.claude/settings`   | `.github/hooks/`      | `.github/hooks/`      |
//! | event case    | PascalCase           | camelCase             | PascalCase            |
//!
//! # Session identity
//! The VS Code sidebar provides `sessionId` directly in every payload.
//! This is used as the persistence key, giving correct per-session taint isolation
//! without needing to derive an ID from `cwd` (as the Copilot CLI adapter does).
//!
//! # Interceptable tools
//! The hook fires for **all** tools the VS Code agent invokes, including:
//! - Built-in file tools: `editFiles`, `createFile`, `readFile`, `deleteFile`
//! - Terminal: `runTerminalCommand`
//! - Network: `#fetch` (web fetch/search tool)
//! - Version control: `pushToGitHub`
//! - MCP tools registered with VS Code
//! - Any future tools added to the VS Code agent tool registry
//!
//! The only agent activity that does NOT fire a hook is the LLM generating
//! text responses — which is not a security-relevant action.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Input — what VS Code sends on stdin
// ---------------------------------------------------------------------------

/// Hook payload sent by VS Code Copilot on stdin before any tool invocation.
///
/// The VS Code format uses a mixed naming convention: common envelope fields
/// use camelCase (`sessionId`, `hookEventName`) while tool-specific fields
/// use snake_case (`tool_name`, `tool_input`) — consistent with how VS Code
/// exposes tool schemas in its agent debug log.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VsCodeHookInput {
    /// ISO-8601 timestamp of the event.
    #[serde(default)]
    pub timestamp: Option<String>,

    /// Absolute workspace path of the current VS Code project.
    /// Stored for audit / tracing; not used as a session key (unlike the
    /// Copilot CLI adapter which derives its session ID from `cwd`).
    pub cwd: String,

    /// Stable identifier for this agent session, provided by VS Code.
    /// Used directly as the persistence key for taint state.
    #[serde(rename = "sessionId")]
    pub session_id: String,

    /// Hook lifecycle event name in PascalCase: `"PreToolUse"`, `"PostToolUse"`,
    /// `"SessionStart"`, `"SessionEnd"`, `"UserPromptSubmit"`, etc.
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,

    /// Path to the agent transcript file (for debugging).
    #[serde(default)]
    pub transcript_path: Option<String>,

    /// Name of the tool being invoked (present for `PreToolUse` / `PostToolUse`).
    /// Snake_case — e.g. `"editFiles"`, `"runTerminalCommand"`, `"#fetch"`.
    #[serde(default)]
    pub tool_name: Option<String>,

    /// Arguments passed to the tool (present for `PreToolUse` / `PostToolUse`).
    /// Structure varies by tool; use the VS Code agent debug log to inspect schemas.
    #[serde(default)]
    pub tool_input: Option<serde_json::Value>,

    /// Unique identifier for this tool invocation (correlates pre/post pairs).
    #[serde(default)]
    pub tool_use_id: Option<String>,

    /// Tool output (present for `PostToolUse` only).
    #[serde(default)]
    pub tool_output: Option<serde_json::Value>,
}

impl VsCodeHookInput {
    /// Normalize this VS Code payload into the internal [`super::HookInput`] format.
    ///
    /// The session ID is taken directly from `sessionId` — no derivation needed.
    /// Tool fields map directly: `tool_name` and `tool_input` are already snake_case.
    pub fn to_hook_input(&self) -> super::HookInput {
        super::HookInput {
            session_id: self.session_id.clone(),
            hook_event_name: self.hook_event_name.clone(),
            tool_name: self.tool_name.clone(),
            tool_input: self.tool_input.clone(),
            tool_output: self.tool_output.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Output — what VS Code expects on stdout
// ---------------------------------------------------------------------------

/// Output written to stdout for VS Code `PreToolUse` hooks.
///
/// VS Code requires the `hookSpecificOutput` wrapper object. The `permissionDecision`
/// field controls whether the tool call proceeds:
/// - `"allow"` — proceed normally
/// - `"deny"` — abort the tool call and show the reason to the user
/// - `"ask"` — pause and ask the user for confirmation
///
/// When multiple hooks run for the same event, VS Code applies the **most
/// restrictive** decision (deny > ask > allow).
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct VsCodePreToolOutput {
    /// Required wrapper expected by VS Code.
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: VsCodePreToolSpecific,
}

/// Fields inside the `hookSpecificOutput` wrapper for `PreToolUse`.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct VsCodePreToolSpecific {
    /// Must be `"PreToolUse"` — VS Code validates this matches the event.
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,

    /// Decision: `"allow"` | `"deny"` | `"ask"`.
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,

    /// Human-readable reason shown to the user on deny or ask.
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission_decision_reason: Option<String>,

    /// Optional additional context injected into the model's conversation.
    /// Use to explain why an action was blocked without breaking the flow.
    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

impl VsCodePreToolOutput {
    /// Allow the tool call to proceed.
    pub fn allow() -> Self {
        Self {
            hook_specific_output: VsCodePreToolSpecific {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                permission_decision_reason: None,
                additional_context: None,
            },
        }
    }

    /// Deny the tool call with a human-readable reason.
    pub fn deny(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            hook_specific_output: VsCodePreToolSpecific {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: Some(reason.clone()),
                additional_context: Some(format!(
                    "This action was blocked by Lilith Zero security policy: {reason}"
                )),
            },
        }
    }

    /// Ask the user for confirmation before proceeding.
    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: VsCodePreToolSpecific {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "ask".to_string(),
                permission_decision_reason: Some(reason.into()),
                additional_context: None,
            },
        }
    }

    /// Serialise to a compact single-line JSON string required by VS Code.
    ///
    /// Infallible: on serialisation failure returns a hardcoded deny to stay fail-closed.
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"internal serialization error"}}"#
                .to_string()
        })
    }
}

/// Output written to stdout for VS Code `PostToolUse` hooks.
///
/// PostToolUse output uses a different top-level structure.
/// `decision: "block"` can prevent the tool result from being fed to the model
/// (e.g. to redact sensitive output). Omitting `decision` means allow.
#[derive(Debug, Serialize, Clone)]
pub struct VsCodePostToolOutput {
    /// Set to `"block"` to suppress the tool result from the model context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,

    /// Human-readable reason (required when `decision` is `"block"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Additional context to inject into the conversation after the tool runs.
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: VsCodePostToolSpecific,
}

/// Fields inside the `hookSpecificOutput` wrapper for `PostToolUse`.
#[derive(Debug, Serialize, Clone)]
pub struct VsCodePostToolSpecific {
    /// Must be `"PostToolUse"`.
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,

    /// Optional context injected into the model's next turn.
    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

impl VsCodePostToolOutput {
    /// Allow the tool result through to the model.
    pub fn allow() -> Self {
        Self {
            decision: None,
            reason: None,
            hook_specific_output: VsCodePostToolSpecific {
                hook_event_name: "PostToolUse".to_string(),
                additional_context: None,
            },
        }
    }

    /// Block the tool result from reaching the model (e.g. to redact secrets).
    pub fn block(reason: impl Into<String>) -> Self {
        Self {
            decision: Some("block".to_string()),
            reason: Some(reason.into()),
            hook_specific_output: VsCodePostToolSpecific {
                hook_event_name: "PostToolUse".to_string(),
                additional_context: None,
            },
        }
    }

    /// Serialise to a compact single-line JSON string.
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"hookSpecificOutput":{"hookEventName":"PostToolUse"}}"#.to_string()
        })
    }
}

/// Output for non-tool VS Code hook events (SessionStart, SessionEnd, UserPromptSubmit).
/// VS Code ignores stdout for these events; we write a minimal valid response
/// for log consistency and future compatibility.
#[derive(Debug, Serialize, Clone)]
pub struct VsCodeGenericOutput {
    /// Required hookSpecificOutput wrapper.
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: VsCodeGenericSpecific,
}

/// Fields inside the hookSpecificOutput wrapper for non-tool events.
#[derive(Debug, Serialize, Clone)]
pub struct VsCodeGenericSpecific {
    /// The hook event name (e.g. "SessionStart").
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
}

impl VsCodeGenericOutput {
    /// Construct a generic output for the given event name.
    pub fn for_event(event_name: impl Into<String>) -> Self {
        Self {
            hook_specific_output: VsCodeGenericSpecific {
                hook_event_name: event_name.into(),
            },
        }
    }

    /// Serialise to a compact single-line JSON string.
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|_| r#"{"hookSpecificOutput":{"hookEventName":"Unknown"}}"#.to_string())
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- VsCodeHookInput deserialization ---

    #[test]
    fn test_input_deserializes_pre_tool_use_payload() {
        let raw = r#"{
            "timestamp": "2026-02-09T10:30:00.000Z",
            "cwd": "/workspace/my-project",
            "sessionId": "vsc-session-abc-123",
            "hookEventName": "PreToolUse",
            "transcript_path": "/tmp/transcript.json",
            "tool_name": "editFiles",
            "tool_input": {"files": ["src/main.ts"]},
            "tool_use_id": "tu-001"
        }"#;
        let input: VsCodeHookInput = serde_json::from_str(raw).expect("must deserialize");
        assert_eq!(input.session_id, "vsc-session-abc-123");
        assert_eq!(input.hook_event_name, "PreToolUse");
        assert_eq!(input.tool_name.as_deref(), Some("editFiles"));
        assert_eq!(input.cwd, "/workspace/my-project");
    }

    #[test]
    fn test_input_deserializes_run_terminal_command() {
        let raw = r#"{
            "cwd": "/workspace",
            "sessionId": "s1",
            "hookEventName": "PreToolUse",
            "tool_name": "runTerminalCommand",
            "tool_input": {"command": "rm -rf /tmp/test"}
        }"#;
        let input: VsCodeHookInput = serde_json::from_str(raw).expect("must deserialize");
        assert_eq!(input.tool_name.as_deref(), Some("runTerminalCommand"));
        let cmd = &input.tool_input.as_ref().unwrap()["command"];
        assert_eq!(cmd.as_str(), Some("rm -rf /tmp/test"));
    }

    #[test]
    fn test_input_deserializes_post_tool_use_with_output() {
        let raw = r#"{
            "cwd": "/workspace",
            "sessionId": "s1",
            "hookEventName": "PostToolUse",
            "tool_name": "editFiles",
            "tool_input": {"files": ["main.rs"]},
            "tool_output": {"status": "success"}
        }"#;
        let input: VsCodeHookInput = serde_json::from_str(raw).expect("must deserialize");
        assert_eq!(input.hook_event_name, "PostToolUse");
        assert!(input.tool_output.is_some());
    }

    #[test]
    fn test_input_deserializes_session_start() {
        let raw = r#"{
            "cwd": "/workspace",
            "sessionId": "s1",
            "hookEventName": "SessionStart"
        }"#;
        let input: VsCodeHookInput = serde_json::from_str(raw).expect("must deserialize");
        assert_eq!(input.hook_event_name, "SessionStart");
        assert!(input.tool_name.is_none());
    }

    #[test]
    fn test_to_hook_input_maps_session_id_directly() {
        let input = VsCodeHookInput {
            timestamp: None,
            cwd: "/workspace".to_string(),
            session_id: "vsc-session-xyz".to_string(),
            hook_event_name: "PreToolUse".to_string(),
            transcript_path: None,
            tool_name: Some("editFiles".to_string()),
            tool_input: Some(serde_json::json!({"files": ["a.rs"]})),
            tool_use_id: None,
            tool_output: None,
        };
        let hook = input.to_hook_input();
        assert_eq!(hook.session_id, "vsc-session-xyz");
        assert_eq!(hook.hook_event_name, "PreToolUse");
        assert_eq!(hook.tool_name.as_deref(), Some("editFiles"));
    }

    // --- VsCodePreToolOutput ---

    #[test]
    fn test_pre_tool_output_allow_format() {
        let out = VsCodePreToolOutput::allow();
        let json = out.to_json_line();
        let v: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecision"].as_str(),
            Some("allow")
        );
        assert_eq!(
            v["hookSpecificOutput"]["hookEventName"].as_str(),
            Some("PreToolUse")
        );
    }

    #[test]
    fn test_pre_tool_output_deny_format() {
        let out = VsCodePreToolOutput::deny("blocked by taint rule");
        let json = out.to_json_line();
        let v: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecision"].as_str(),
            Some("deny")
        );
        assert!(v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some());
        // deny should also include additionalContext for model visibility
        assert!(v["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .is_some());
    }

    #[test]
    fn test_pre_tool_output_allow_omits_reason_and_context() {
        let json = VsCodePreToolOutput::allow().to_json_line();
        assert!(
            !json.contains("permissionDecisionReason"),
            "allow must not include reason: {json}"
        );
        assert!(
            !json.contains("additionalContext"),
            "allow must not include additionalContext: {json}"
        );
    }

    #[test]
    fn test_pre_tool_output_is_single_line() {
        let json = VsCodePreToolOutput::deny("test").to_json_line();
        assert!(!json.contains('\n'), "output must be single line: {json}");
    }

    #[test]
    fn test_pre_tool_output_ask_format() {
        let out = VsCodePreToolOutput::ask("needs confirmation");
        let v: serde_json::Value = serde_json::from_str(&out.to_json_line()).expect("valid JSON");
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecision"].as_str(),
            Some("ask")
        );
    }

    // --- VsCodePostToolOutput ---

    #[test]
    fn test_post_tool_output_allow_format() {
        let out = VsCodePostToolOutput::allow();
        let v: serde_json::Value = serde_json::from_str(&out.to_json_line()).expect("valid JSON");
        assert!(
            v.get("decision").is_none() || v["decision"].is_null(),
            "allow must not include decision field"
        );
        assert_eq!(
            v["hookSpecificOutput"]["hookEventName"].as_str(),
            Some("PostToolUse")
        );
    }

    #[test]
    fn test_post_tool_output_block_format() {
        let out = VsCodePostToolOutput::block("sensitive output redacted");
        let v: serde_json::Value = serde_json::from_str(&out.to_json_line()).expect("valid JSON");
        assert_eq!(v["decision"].as_str(), Some("block"));
        assert!(v["reason"].as_str().is_some());
    }

    // --- VsCodeGenericOutput ---

    #[test]
    fn test_generic_output_for_session_start() {
        let out = VsCodeGenericOutput::for_event("SessionStart");
        let v: serde_json::Value = serde_json::from_str(&out.to_json_line()).expect("valid JSON");
        assert_eq!(
            v["hookSpecificOutput"]["hookEventName"].as_str(),
            Some("SessionStart")
        );
    }
}
