//! Integration tests for Claude Code hook format support.
//!
//! These tests run the real `lilith-zero` binary with `--format claude` (the
//! default) and verify security-critical behaviour end-to-end.
//!
//! # Claude Code hook contract
//! - Exit code 0  → allow (Claude Code proceeds with the tool call).
//! - Exit code 2  → deny/block (Claude Code blocks the tool call).
//! - stdout       → ignored by Claude Code; we verify it is empty on allow.
//! - stderr       → audit/debug output; not checked here.
//! - Input JSON   → `{"session_id":…, "hook_event_name":…, "tool_name":…, "tool_input":…}`
//!
//! # Test naming convention
//! `test_claude_{scenario}_{expected_outcome}`
//!
//! All tests are self-contained and work in any environment that has the
//! compiled binary (`cargo build`) and a writable temp directory.

#![cfg(not(miri))]

use assert_cmd::Command;
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lilith-zero"))
}

fn write_temp_policy(yaml: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("failed to create temp policy file");
    f.write_all(yaml.as_bytes())
        .expect("failed to write policy");
    f
}

fn default_policy_yaml() -> &'static str {
    r#"
id: claude-test-policy
customer_id: test-customer
name: Claude Test Policy
version: 1
static_rules:
  allowed_tool: ALLOW
  forbidden_tool: DENY
taint_rules: []
resource_rules: []
"#
}

/// Run `lilith-zero hook` (default `--format claude`) with the given stdin JSON.
fn run_claude_hook(
    input_json: &str,
    policy_path: &std::path::Path,
) -> assert_cmd::assert::Assert {
    let mut cmd = Command::new(bin_path());
    cmd.arg("hook")
        .arg("--format")
        .arg("claude")
        .arg("--policy")
        .arg(policy_path)
        .write_stdin(input_json.as_bytes().to_vec());
    cmd.assert()
}

// ---------------------------------------------------------------------------
// Core allow / deny behaviour
// ---------------------------------------------------------------------------

/// An allowed tool must exit with code 0.
#[test]
fn test_claude_pre_tool_use_allowed_tool_exits_0() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"session_id":"claude-test-allow","hook_event_name":"PreToolUse","tool_name":"allowed_tool","tool_input":{}}"#;

    run_claude_hook(input, policy.path())
        .code(0); // exit 0 = allow
}

/// A denied tool must exit with code 2.
/// Claude Code treats any exit code 2 as "block the tool call."
#[test]
fn test_claude_pre_tool_use_denied_tool_exits_2() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"session_id":"claude-test-deny","hook_event_name":"PreToolUse","tool_name":"forbidden_tool","tool_input":{}}"#;

    run_claude_hook(input, policy.path())
        .code(2); // exit 2 = deny
}

/// An allowed tool must produce no output on stdout — Claude Code ignores stdout
/// for the decision and any unexpected output could confuse it.
#[test]
fn test_claude_allow_produces_no_stdout() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"session_id":"claude-stdout-allow","hook_event_name":"PreToolUse","tool_name":"allowed_tool","tool_input":{}}"#;

    let output = run_claude_hook(input, policy.path())
        .code(0)
        .get_output()
        .stdout
        .clone();

    assert!(
        output.is_empty(),
        "allow must produce no stdout; got: {}",
        String::from_utf8_lossy(&output)
    );
}

// ---------------------------------------------------------------------------
// Fail-closed security invariants
// ---------------------------------------------------------------------------

/// Malformed JSON on stdin must exit 1 or some non-zero code (not 0 = allow).
/// Claude Code hook format exits non-zero on parse error — fail-closed.
#[test]
fn test_claude_malformed_json_fails_closed() {
    let policy = write_temp_policy(default_policy_yaml());

    let mut cmd = Command::new(bin_path());
    cmd.arg("hook")
        .arg("--format")
        .arg("claude")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(b"{ not valid json !!!".to_vec());

    // Must NOT exit 0 (that would be a silent allow on broken input).
    let output = cmd.assert().get_output().clone();
    assert_ne!(
        output.status.code(),
        Some(0),
        "malformed JSON must not produce exit code 0 (allow)"
    );
}

/// Empty stdin must exit non-zero (fail-closed).
#[test]
fn test_claude_empty_stdin_fails_closed() {
    let policy = write_temp_policy(default_policy_yaml());

    let mut cmd = Command::new(bin_path());
    cmd.arg("hook")
        .arg("--format")
        .arg("claude")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(b"".to_vec());

    let output = cmd.assert().get_output().clone();
    assert_ne!(
        output.status.code(),
        Some(0),
        "empty stdin must not produce exit code 0 (allow)"
    );
}

/// A tool that is not listed in the policy must be denied (fail-closed default).
#[test]
fn test_claude_unlisted_tool_denied_fail_closed() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"session_id":"claude-unknown","hook_event_name":"PreToolUse","tool_name":"mystery_unlisted_tool","tool_input":{}}"#;

    run_claude_hook(input, policy.path())
        .code(2); // unknown → deny (fail-closed)
}

/// No policy file → all tools must be denied (fail-closed, no policy = deny all).
#[test]
fn test_claude_no_policy_denies_all() {
    let input = r#"{"session_id":"claude-no-policy","hook_event_name":"PreToolUse","tool_name":"allowed_tool","tool_input":{}}"#;

    let mut cmd = Command::new(bin_path());
    cmd.arg("hook")
        .arg("--format")
        .arg("claude")
        // No --policy flag: engine falls back to deny-all
        .write_stdin(input.as_bytes().to_vec());

    let output = cmd.assert().get_output().clone();
    // Must not exit 0 (allow) when no policy is loaded.
    assert_ne!(
        output.status.code(),
        Some(0),
        "no policy must result in deny (non-zero exit), not allow"
    );
}

// ---------------------------------------------------------------------------
// Event routing
// ---------------------------------------------------------------------------

/// PostToolUse events must exit 0 (always allowed — used for taint propagation,
/// not for blocking tool output in the Claude Code format).
#[test]
fn test_claude_post_tool_use_exits_0() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"session_id":"claude-post","hook_event_name":"PostToolUse","tool_name":"forbidden_tool","tool_input":null,"tool_output":{"result":"some output"}}"#;

    run_claude_hook(input, policy.path())
        .code(0);
}

/// Unknown event names must exit 0 (pass-through: unknown events are allowed
/// by default so future Claude Code events don't break existing deployments).
#[test]
fn test_claude_unknown_event_exits_0() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"session_id":"claude-unknown-event","hook_event_name":"FutureNewEvent","tool_name":"forbidden_tool","tool_input":{}}"#;

    run_claude_hook(input, policy.path())
        .code(0);
}

// ---------------------------------------------------------------------------
// Taint propagation across invocations
// ---------------------------------------------------------------------------

/// A taint added in call 1 must block the check tool in call 2.
/// This verifies the derive_session_id → persistence → taint bleed-through chain
/// for the Claude Code format (session_id is supplied directly in the payload).
#[test]
fn test_claude_taint_persists_across_hook_invocations() {
    let policy_yaml = r#"
id: claude-taint-test
customer_id: test
name: Claude Taint Test
version: 1
static_rules:
  taint_tool: ALLOW
  check_tool: ALLOW
taint_rules:
  - tool: taint_tool
    action: ADD_TAINT
    tag: CLAUDE_TEST_TAINT
  - tool: check_tool
    action: CHECK_TAINT
    required_taints: ["CLAUDE_TEST_TAINT"]
    error: "blocked by CLAUDE_TEST_TAINT"
resource_rules: []
"#;
    let policy = write_temp_policy(policy_yaml);

    // Use a unique session ID per test run to avoid state bleed from other tests.
    let session_id = format!("claude-taint-persist-{}", std::process::id());

    // Call 1: invoke taint_tool → adds CLAUDE_TEST_TAINT.
    let input1 = format!(
        r#"{{"session_id":"{session_id}","hook_event_name":"PreToolUse","tool_name":"taint_tool","tool_input":{{}}}}"#
    );
    run_claude_hook(&input1, policy.path())
        .code(0); // taint_tool is ALLOW

    // Call 2: invoke check_tool → must be blocked (CLAUDE_TEST_TAINT is active).
    let input2 = format!(
        r#"{{"session_id":"{session_id}","hook_event_name":"PreToolUse","tool_name":"check_tool","tool_input":{{}}}}"#
    );
    run_claude_hook(&input2, policy.path())
        .code(2); // blocked by CLAUDE_TEST_TAINT

    // Cleanup session file
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let session_path = std::path::PathBuf::from(home)
        .join(".lilith")
        .join("sessions")
        .join(format!("{session_id}.json"));
    let _ = std::fs::remove_file(session_path);
}
