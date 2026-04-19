// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

//! GitHub Copilot hook format support.
//!
//! Copilot hooks send JSON events to a binary via stdin and read a JSON
//! permission decision from stdout. This module provides:
//!
//! - [`CopilotHookInput`] — the stdin payload for all Copilot hook events.
//! - [`CopilotHookOutput`] — the stdout JSON response for `preToolUse`.
//! - [`derive_session_id`] — maps a workspace `cwd` to a stable session ID
//!   (Copilot has no native session_id concept).
//! - [`normalize_event_name`] — translates Copilot camelCase event names to
//!   the PascalCase names used by the existing `HookHandler` routing logic.
//!
//! # Copilot vs Claude Code hook differences
//!
//! | Aspect        | Claude Code              | GitHub Copilot            |
//! |---------------|--------------------------|---------------------------|
//! | Event name    | `hook_event_name` in JSON | `--event` CLI flag        |
//! | Case          | PascalCase (`PreToolUse`)| camelCase (`preToolUse`)  |
//! | Session ID    | `session_id` in JSON     | derived from `cwd` hash   |
//! | Allow signal  | Exit code 0              | `{"permissionDecision":"allow"}` on stdout |
//! | Deny signal   | Exit code 2              | `{"permissionDecision":"deny",...}` on stdout |
//! | Exit code     | Meaningful (0 or 2)      | Always 0 (ignored)        |

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Unified GitHub Copilot hook payload delivered on stdin.
///
/// Copilot sends one JSON object per invocation. The shape is the same for all
/// event types; optional fields are populated depending on which event fired.
///
/// # Field availability by event
///
/// | Field          | preToolUse | postToolUse | sessionStart | sessionEnd |
/// |----------------|------------|-------------|--------------|------------|
/// | `timestamp`    | ✓          | ✓           | ✓            | ✓          |
/// | `cwd`          | ✓          | ✓           | ✓            | ✓          |
/// | `tool_name`    | ✓          | ✓           |              |            |
/// | `tool_args`    | ✓          | ✓           |              |            |
/// | `tool_result`  |            | ✓           |              |            |
/// | `source`       |            |             | ✓            |            |
/// | `initial_prompt`|           |             | ✓            |            |
/// | `reason`       |            |             |              | ✓          |
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CopilotHookInput {
    /// Unix timestamp in milliseconds when the event was emitted.
    #[serde(default)]
    pub timestamp: Option<i64>,

    /// Absolute path of the current working directory for this Copilot session.
    pub cwd: String,

    /// Stable session UUID provided by the Copilot CLI (present in gh copilot CLI v1.0+).
    ///
    /// When present, this is used directly as the session key for taint persistence,
    /// giving correct per-session isolation. When absent (older CLI versions or the
    /// cloud agent), the session ID is derived from `cwd` via SHA-256.
    #[serde(rename = "sessionId", default)]
    pub session_id: Option<String>,

    /// Name of the tool being invoked (present for `preToolUse` / `postToolUse`).
    #[serde(rename = "toolName", default)]
    pub tool_name: Option<String>,

    /// Tool arguments serialised as a JSON **string** (double-encoded by Copilot).
    ///
    /// The outer JSON contains this field as a string value; callers must
    /// `serde_json::from_str` the inner value to obtain the argument map.
    #[serde(rename = "toolArgs", default)]
    pub tool_args: Option<String>,

    /// Execution result (present for `postToolUse` only).
    #[serde(rename = "toolResult", default)]
    pub tool_result: Option<CopilotToolResult>,

    /// Session start reason (present for `sessionStart` only).
    /// Values: `"new"` | `"resume"` | `"startup"`.
    #[serde(default)]
    pub source: Option<String>,

    /// Session end reason (present for `sessionEnd` only).
    /// Values: `"complete"` | `"error"` | `"abort"` | `"timeout"` | `"user_exit"`.
    #[serde(default)]
    pub reason: Option<String>,

    /// Initial user prompt (present for `sessionStart` only).
    #[serde(rename = "initialPrompt", default)]
    pub initial_prompt: Option<String>,
}

impl CopilotHookInput {
    /// Decode `tool_args` from its JSON-string wrapper into a JSON value.
    ///
    /// Returns `serde_json::Value::Null` if the field is absent or unparseable.
    /// Callers should treat a `Null` result as an empty argument set, not as an
    /// error, because some legitimate tools have no arguments.
    pub fn decoded_tool_args(&self) -> serde_json::Value {
        self.tool_args
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::Value::Null)
    }
}

/// Describes the outcome of a tool execution in a `postToolUse` event.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CopilotToolResult {
    /// Outcome category: `"success"` | `"failure"` | `"denied"`.
    #[serde(rename = "resultType")]
    pub result_type: String,

    /// Human-readable result text that Copilot will forward to the LLM context.
    #[serde(rename = "textResultForLlm", default)]
    pub text_result: Option<String>,
}

/// Permission decision written to stdout for Copilot `preToolUse` hooks.
///
/// Copilot reads one line of JSON from the hook process's stdout and applies
/// the `permissionDecision`. All other events ignore stdout output.
///
/// # Security note
/// Only `"deny"` is actively enforced by Copilot at the time of writing.
/// We always write a decision regardless so that future Copilot versions can
/// act on `"allow"` without requiring hook changes.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct CopilotHookOutput {
    /// Permission decision forwarded to Copilot.
    /// Valid values: `"allow"` | `"deny"` | `"ask"`.
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,

    /// Human-readable explanation shown to the user on `"deny"` or `"ask"`.
    /// Omitted when `permission_decision` is `"allow"`.
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub permission_decision_reason: Option<String>,
}

impl CopilotHookOutput {
    /// Construct an `allow` decision.
    pub fn allow() -> Self {
        Self {
            permission_decision: "allow".to_string(),
            permission_decision_reason: None,
        }
    }

    /// Construct a `deny` decision with a human-readable `reason`.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            permission_decision: "deny".to_string(),
            permission_decision_reason: Some(reason.into()),
        }
    }

    /// Construct an `ask` decision (request human confirmation).
    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            permission_decision: "ask".to_string(),
            permission_decision_reason: Some(reason.into()),
        }
    }

    /// Serialise to a compact, single-line JSON string.
    ///
    /// Copilot requires the entire response on one line. This method is
    /// infallible: if serialisation somehow fails, it returns a hardcoded
    /// deny string so we remain fail-closed even in that extreme edge case.
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            // This branch is unreachable in practice but satisfies the
            // fail-closed requirement: never silently allow on error.
            r#"{"permissionDecision":"deny","permissionDecisionReason":"internal serialization error"}"#
                .to_string()
        })
    }
}

/// Derive a stable, filesystem-safe session ID from a workspace path.
///
/// Copilot does not expose a session identifier. We hash the `cwd` (current
/// working directory) with SHA-256 to produce a deterministic, per-workspace
/// session key. The first 16 bytes of the hash give 128 bits of uniqueness —
/// identical to UUID v4 entropy and sufficient to avoid accidental collisions
/// across any realistic set of developer workspaces.
///
/// The `copilot-` prefix distinguishes these IDs from Claude Code session IDs
/// in shared audit logs and the `~/.lilith/sessions/` store.
///
/// # Security properties
/// - Deterministic: same `cwd` always maps to the same session.
/// - Collision-resistant: different `cwd` values are overwhelmingly unlikely
///   to produce the same ID.
/// - No path traversal: the output contains only hex digits and a hyphen,
///   making it safe to use as a filename component (validated by
///   `PersistenceLayer::sanitize_session_id`).
pub fn derive_session_id(cwd: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cwd.as_bytes());
    let hash = hasher.finalize();
    format!("copilot-{}", hex::encode(&hash[..16]))
}

/// Map a Copilot camelCase event name to the PascalCase name used internally.
///
/// The `HookHandler` router uses Claude Code's PascalCase convention
/// (`"PreToolUse"`, `"PostToolUse"`). This function translates so that
/// Copilot events can be dispatched through the same routing logic.
///
/// Unknown event names are mapped to `"Unknown"` which hits the catch-all
/// branch in `HookHandler::handle()` and returns exit code 0 (allow).
pub fn normalize_event_name(copilot_event: &str) -> &'static str {
    match copilot_event {
        "preToolUse" => "PreToolUse",
        "postToolUse" => "PostToolUse",
        "sessionStart" => "SessionStart",
        "sessionEnd" => "SessionEnd",
        "userPromptSubmitted" => "UserPromptSubmitted",
        "errorOccurred" => "ErrorOccurred",
        _ => "Unknown",
    }
}

/// Returns `true` for Copilot events whose stdout output is ignored by Copilot.
///
/// Only `preToolUse` output is actioned. All other events produce output that
/// Copilot silently discards, but we still write a valid JSON response so logs
/// are consistent and future Copilot versions can opt in without hook changes.
pub fn is_output_ignored_event(normalized_event: &str) -> bool {
    !matches!(normalized_event, "PreToolUse")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- derive_session_id ---

    /// Session IDs must be deterministic: the same workspace path must always
    /// produce the same ID so that taint state persists across hook invocations.
    #[test]
    fn test_derive_session_id_is_deterministic() {
        let id1 = derive_session_id("/home/user/my-project");
        let id2 = derive_session_id("/home/user/my-project");
        assert_eq!(id1, id2, "same cwd must always produce the same session ID");
    }

    /// Different workspaces must not share a session ID — that would let taints
    /// bleed across unrelated projects.
    #[test]
    fn test_derive_session_id_different_cwds_produce_different_ids() {
        let id_a = derive_session_id("/home/user/project-a");
        let id_b = derive_session_id("/home/user/project-b");
        assert_ne!(
            id_a, id_b,
            "different cwds must produce different session IDs"
        );
    }

    /// IDs must start with "copilot-" to distinguish them from Claude Code IDs
    /// in shared audit logs and session files.
    #[test]
    fn test_derive_session_id_has_copilot_prefix() {
        let id = derive_session_id("/workspace");
        assert!(
            id.starts_with("copilot-"),
            "session ID must start with 'copilot-' but got: {id}"
        );
    }

    /// IDs must be safe as filenames: only hex digits and the prefix hyphen.
    #[test]
    fn test_derive_session_id_is_filesystem_safe() {
        let id = derive_session_id("/home/user/projects/my repo with spaces");
        for ch in id.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-',
                "session ID contains unsafe char '{ch}' in: {id}"
            );
        }
    }

    /// Empty cwd must still produce a valid (not panicking) session ID.
    #[test]
    fn test_derive_session_id_empty_cwd() {
        let id = derive_session_id("");
        assert!(
            id.starts_with("copilot-"),
            "empty cwd must still produce a valid ID"
        );
        assert!(!id.is_empty());
    }

    // --- normalize_event_name ---

    #[test]
    fn test_normalize_event_name_pre_tool_use() {
        assert_eq!(normalize_event_name("preToolUse"), "PreToolUse");
    }

    #[test]
    fn test_normalize_event_name_post_tool_use() {
        assert_eq!(normalize_event_name("postToolUse"), "PostToolUse");
    }

    #[test]
    fn test_normalize_event_name_session_start() {
        assert_eq!(normalize_event_name("sessionStart"), "SessionStart");
    }

    #[test]
    fn test_normalize_event_name_session_end() {
        assert_eq!(normalize_event_name("sessionEnd"), "SessionEnd");
    }

    #[test]
    fn test_normalize_event_name_unknown_maps_to_unknown() {
        assert_eq!(normalize_event_name("bogusEvent"), "Unknown");
        assert_eq!(normalize_event_name(""), "Unknown");
        assert_eq!(normalize_event_name("PreToolUse"), "Unknown"); // must be camelCase
    }

    // --- is_output_ignored_event ---

    #[test]
    fn test_pre_tool_use_output_is_not_ignored() {
        assert!(
            !is_output_ignored_event("PreToolUse"),
            "preToolUse output must be processed by Copilot"
        );
    }

    #[test]
    fn test_post_tool_use_output_is_ignored() {
        assert!(
            is_output_ignored_event("PostToolUse"),
            "postToolUse output is ignored by Copilot"
        );
    }

    #[test]
    fn test_session_start_output_is_ignored() {
        assert!(is_output_ignored_event("SessionStart"));
    }

    // --- CopilotHookOutput ---

    #[test]
    fn test_output_allow_has_correct_decision() {
        let out = CopilotHookOutput::allow();
        assert_eq!(out.permission_decision, "allow");
        assert!(
            out.permission_decision_reason.is_none(),
            "allow should not include a reason"
        );
    }

    #[test]
    fn test_output_deny_has_correct_decision_and_reason() {
        let out = CopilotHookOutput::deny("blocked by policy");
        assert_eq!(out.permission_decision, "deny");
        assert_eq!(
            out.permission_decision_reason.as_deref(),
            Some("blocked by policy")
        );
    }

    #[test]
    fn test_output_ask_has_correct_decision_and_reason() {
        let out = CopilotHookOutput::ask("needs human approval");
        assert_eq!(out.permission_decision, "ask");
        assert_eq!(
            out.permission_decision_reason.as_deref(),
            Some("needs human approval")
        );
    }

    /// Copilot requires the entire response on a single line with no embedded newlines.
    #[test]
    fn test_output_to_json_line_contains_no_newlines() {
        let allow = CopilotHookOutput::allow().to_json_line();
        let deny = CopilotHookOutput::deny("test reason").to_json_line();
        assert!(!allow.contains('\n'), "allow output must be a single line");
        assert!(!deny.contains('\n'), "deny output must be a single line");
    }

    /// The JSON line must be parseable back to the original structure.
    #[test]
    fn test_output_to_json_line_is_valid_json() {
        let json = CopilotHookOutput::deny("blocked").to_json_line();
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("output must be valid JSON");
        assert_eq!(
            parsed["permissionDecision"].as_str(),
            Some("deny"),
            "permissionDecision must round-trip through JSON"
        );
    }

    /// Serialised allow must NOT include a `permissionDecisionReason` key at all
    /// (not even `null`) since Copilot may reject unexpected fields.
    #[test]
    fn test_output_allow_omits_reason_field() {
        let json = CopilotHookOutput::allow().to_json_line();
        assert!(
            !json.contains("permissionDecisionReason"),
            "allow output must not include reason field, got: {json}"
        );
    }

    // --- CopilotHookInput deserialization ---

    #[test]
    fn test_input_deserializes_pre_tool_use_payload() {
        let raw = r#"{
            "timestamp": 1704614600000,
            "cwd": "/home/user/project",
            "toolName": "bash",
            "toolArgs": "{\"command\":\"ls -la\"}"
        }"#;
        let input: CopilotHookInput =
            serde_json::from_str(raw).expect("valid preToolUse payload must deserialize");
        assert_eq!(input.cwd, "/home/user/project");
        assert_eq!(input.tool_name.as_deref(), Some("bash"));
        assert!(input.tool_result.is_none());
    }

    #[test]
    fn test_input_deserializes_post_tool_use_payload() {
        let raw = r#"{
            "timestamp": 1704614700000,
            "cwd": "/home/user/project",
            "toolName": "bash",
            "toolArgs": "{\"command\":\"ls\"}",
            "toolResult": {
                "resultType": "success",
                "textResultForLlm": "file1.txt\nfile2.txt"
            }
        }"#;
        let input: CopilotHookInput =
            serde_json::from_str(raw).expect("valid postToolUse payload must deserialize");
        let result = input
            .tool_result
            .as_ref()
            .expect("toolResult must be present");
        assert_eq!(result.result_type, "success");
        assert_eq!(result.text_result.as_deref(), Some("file1.txt\nfile2.txt"));
    }

    #[test]
    fn test_input_deserializes_session_start_payload() {
        let raw = r#"{
            "timestamp": 1704614400000,
            "cwd": "/home/user/project",
            "source": "new",
            "initialPrompt": "Create a new feature"
        }"#;
        let input: CopilotHookInput =
            serde_json::from_str(raw).expect("valid sessionStart payload must deserialize");
        assert_eq!(input.source.as_deref(), Some("new"));
        assert_eq!(
            input.initial_prompt.as_deref(),
            Some("Create a new feature")
        );
        assert!(input.tool_name.is_none());
    }

    #[test]
    fn test_input_deserializes_session_end_payload() {
        let raw = r#"{
            "timestamp": 1704618000000,
            "cwd": "/home/user/project",
            "reason": "complete"
        }"#;
        let input: CopilotHookInput =
            serde_json::from_str(raw).expect("valid sessionEnd payload must deserialize");
        assert_eq!(input.reason.as_deref(), Some("complete"));
    }

    /// All optional fields missing — only `cwd` is required.
    /// This test guards against regressions where new required fields would
    /// break parsing of minimal payloads from older Copilot versions.
    #[test]
    fn test_input_deserializes_minimal_payload_with_only_cwd() {
        let raw = r#"{"cwd": "/workspace"}"#;
        let input: CopilotHookInput =
            serde_json::from_str(raw).expect("minimal payload with only cwd must deserialize");
        assert_eq!(input.cwd, "/workspace");
        assert!(input.tool_name.is_none());
        assert!(input.tool_result.is_none());
        assert!(input.timestamp.is_none());
    }

    // --- decoded_tool_args ---

    #[test]
    fn test_decoded_tool_args_parses_json_string() {
        let input = CopilotHookInput {
            timestamp: None,
            cwd: "/workspace".to_string(),
            session_id: None,
            tool_name: Some("bash".to_string()),
            tool_args: Some(r#"{"command":"ls -la"}"#.to_string()),
            tool_result: None,
            source: None,
            reason: None,
            initial_prompt: None,
        };
        let args = input.decoded_tool_args();
        assert_eq!(args["command"].as_str(), Some("ls -la"));
    }

    /// If `tool_args` is absent, `decoded_tool_args` must return `Null` (not panic).
    #[test]
    fn test_decoded_tool_args_returns_null_when_absent() {
        let input = CopilotHookInput {
            timestamp: None,
            cwd: "/workspace".to_string(),
            session_id: None,
            tool_name: Some("no_args_tool".to_string()),
            tool_args: None,
            tool_result: None,
            source: None,
            reason: None,
            initial_prompt: None,
        };
        assert_eq!(input.decoded_tool_args(), serde_json::Value::Null);
    }

    /// If `tool_args` contains invalid JSON, `decoded_tool_args` must return
    /// `Null` rather than panicking or propagating an error. Malformed args
    /// are handled fail-closed at the handler level (policy evaluates with
    /// empty arguments rather than crashing).
    #[test]
    fn test_decoded_tool_args_returns_null_for_invalid_json_string() {
        let input = CopilotHookInput {
            timestamp: None,
            cwd: "/workspace".to_string(),
            session_id: None,
            tool_name: Some("bash".to_string()),
            tool_args: Some("not valid json {{{{".to_string()),
            tool_result: None,
            source: None,
            reason: None,
            initial_prompt: None,
        };
        assert_eq!(input.decoded_tool_args(), serde_json::Value::Null);
    }
}
