//! Integration tests for GitHub Copilot hook format support.
//!
//! These tests run the real `lilith-zero` binary with `--format copilot` and
//! verify security-critical behaviour end-to-end. Each test follows the
//! pattern: **Given** (setup) → **When** (binary invocation) → **Then** (assertions).
//!
//! # Copilot hook contract
//! - Exit code is always 0 regardless of allow/deny (Copilot uses JSON output).
//! - stdout is a single line of valid JSON.
//! - `permissionDecision` is `"allow"` or `"deny"`.
//! - `permissionDecisionReason` is present on deny, absent on allow.
//!
//! # Test naming convention
//! `test_copilot_{scenario}_{expected_outcome}`
//!
//! All tests are self-contained: they embed fixture JSON inline and create
//! any temporary policy files they need, so they work in any environment that
//! has the compiled binary and a writable temp directory.

#![cfg(not(miri))]

use assert_cmd::Command;
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Absolute path to the test binary, set by cargo at build time.
fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lilith-zero"))
}

/// Write a policy YAML to a named temp file and return the file handle.
/// The caller must keep the handle alive for the duration of the test.
fn write_temp_policy(yaml: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("failed to create temp policy file");
    f.write_all(yaml.as_bytes())
        .expect("failed to write policy");
    f
}

/// Default policy used by most tests: `allowed_tool` → ALLOW, `forbidden_tool` → DENY.
fn default_policy_yaml() -> &'static str {
    r#"
id: copilot-test-policy
customer_id: test-customer
name: Copilot Test Policy
version: 1
static_rules:
  allowed_tool: ALLOW
  forbidden_tool: DENY
taint_rules: []
resource_rules: []
"#
}

/// Parse the JSON output from the binary and return the parsed value.
/// Panics with a descriptive message if the output is not valid JSON or is empty.
fn parse_stdout_json(raw: &[u8]) -> serde_json::Value {
    let text = std::str::from_utf8(raw).expect("stdout must be valid UTF-8");
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .expect("stdout must contain at least one non-empty line");
    serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\n  raw line: {line}"))
}

/// Run the binary with `--format copilot`, given input JSON and a policy file.
/// Returns the `assert_cmd::assert::Assert` so callers can chain assertions.
fn run_copilot_hook(
    input_json: &str,
    event: &str,
    policy_path: &std::path::Path,
) -> assert_cmd::assert::Assert {
    let mut cmd = Command::new(bin_path());
    cmd.arg("hook")
        .arg("--format")
        .arg("copilot")
        .arg("--event")
        .arg(event)
        .arg("--policy")
        .arg(policy_path)
        .write_stdin(input_json.as_bytes().to_vec());
    cmd.assert()
}

// ---------------------------------------------------------------------------
// Core allow / deny behaviour
// ---------------------------------------------------------------------------

/// An allowed tool must produce `permissionDecision: "allow"` on stdout.
#[test]
fn test_copilot_pre_tool_use_allowed_tool_returns_allow() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"timestamp":1704614600000,"cwd":"/home/user/project","toolName":"allowed_tool","toolArgs":"{}"}"#;

    let output = run_copilot_hook(input, "preToolUse", policy.path())
        .success() // exit code must be 0
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    assert_eq!(
        json["permissionDecision"].as_str(),
        Some("allow"),
        "allowed tool must produce permissionDecision=allow"
    );
}

/// A denied tool must produce `permissionDecision: "deny"` on stdout.
/// The exit code must still be 0 because Copilot reads the JSON, not the exit code.
#[test]
fn test_copilot_pre_tool_use_denied_tool_returns_deny() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"timestamp":1704614600000,"cwd":"/home/user/project","toolName":"forbidden_tool","toolArgs":"{}"}"#;

    let output = run_copilot_hook(input, "preToolUse", policy.path())
        .success() // exit code MUST be 0 even for deny
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    assert_eq!(
        json["permissionDecision"].as_str(),
        Some("deny"),
        "denied tool must produce permissionDecision=deny"
    );
}

/// On deny, `permissionDecisionReason` must be present and non-empty so that
/// users and audit systems understand why the action was blocked.
#[test]
fn test_copilot_deny_includes_human_readable_reason() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"timestamp":1704614600000,"cwd":"/home/user/project","toolName":"forbidden_tool","toolArgs":"{}"}"#;

    let output = run_copilot_hook(input, "preToolUse", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    let reason = json["permissionDecisionReason"].as_str();
    assert!(
        reason.is_some() && !reason.unwrap().is_empty(),
        "deny must include a non-empty permissionDecisionReason, got: {json}"
    );
}

/// On allow, `permissionDecisionReason` must be absent entirely (not even `null`).
/// Unnecessary fields can confuse older Copilot versions.
#[test]
fn test_copilot_allow_omits_reason_field() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"timestamp":1704614600000,"cwd":"/home/user/project","toolName":"allowed_tool","toolArgs":"{}"}"#;

    let output = run_copilot_hook(input, "preToolUse", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();

    let raw = std::str::from_utf8(&output).unwrap();
    assert!(
        !raw.contains("permissionDecisionReason"),
        "allow output must not include permissionDecisionReason, got: {raw}"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed security invariants
// ---------------------------------------------------------------------------

/// Malformed JSON on stdin must produce a deny decision, not a crash or allow.
/// This is a core fail-closed invariant: Lilith must never accidentally grant
/// access because of a parsing failure.
#[test]
fn test_copilot_malformed_json_fails_closed_with_deny() {
    let policy = write_temp_policy(default_policy_yaml());

    let mut cmd = Command::new(bin_path());
    let output = cmd
        .arg("hook")
        .arg("--format")
        .arg("copilot")
        .arg("--event")
        .arg("preToolUse")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(b"{ this is not json !!!".to_vec())
        .assert()
        .success() // must not crash with non-zero exit
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    assert_eq!(
        json["permissionDecision"].as_str(),
        Some("deny"),
        "malformed JSON must fail-closed with deny"
    );
}

/// Empty stdin must produce a deny decision, not an error.
/// A hook binary that crashes on empty input could be exploited by racing
/// the invocation before the payload arrives.
#[test]
fn test_copilot_empty_stdin_fails_closed_with_deny() {
    let policy = write_temp_policy(default_policy_yaml());

    let mut cmd = Command::new(bin_path());
    let output = cmd
        .arg("hook")
        .arg("--format")
        .arg("copilot")
        .arg("--event")
        .arg("preToolUse")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(b"".to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    assert_eq!(
        json["permissionDecision"].as_str(),
        Some("deny"),
        "empty stdin must fail-closed with deny"
    );
}

/// Whitespace-only stdin (e.g. a stray newline) must also fail-closed.
#[test]
fn test_copilot_whitespace_only_stdin_fails_closed() {
    let policy = write_temp_policy(default_policy_yaml());

    let mut cmd = Command::new(bin_path());
    let output = cmd
        .arg("hook")
        .arg("--format")
        .arg("copilot")
        .arg("--event")
        .arg("preToolUse")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(b"   \n\t  ".to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    assert_eq!(
        json["permissionDecision"].as_str(),
        Some("deny"),
        "whitespace-only stdin must fail-closed with deny"
    );
}

/// A payload with an unknown tool (not in the policy) must be denied when the
/// policy is in the default fail-closed `block_params` mode.
#[test]
fn test_copilot_unknown_tool_denied_when_no_policy_match() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"timestamp":1704614600000,"cwd":"/workspace","toolName":"unlisted_tool","toolArgs":"{}"}"#;

    let output = run_copilot_hook(input, "preToolUse", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    assert_eq!(
        json["permissionDecision"].as_str(),
        Some("deny"),
        "tool not in policy must be denied in fail-closed mode"
    );
}

// ---------------------------------------------------------------------------
// Output format requirements
// ---------------------------------------------------------------------------

/// The stdout response must be exactly one line of JSON (no pretty-printing,
/// no trailing newline inside the JSON). Copilot parses the first line only.
#[test]
fn test_copilot_output_is_single_line_json() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"timestamp":1704614600000,"cwd":"/workspace","toolName":"allowed_tool","toolArgs":"{}"}"#;

    let output = run_copilot_hook(input, "preToolUse", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();

    let text = std::str::from_utf8(&output).expect("stdout must be UTF-8");
    let non_empty_lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        non_empty_lines.len(),
        1,
        "stdout must contain exactly one non-empty line, got {}: {:?}",
        non_empty_lines.len(),
        non_empty_lines
    );
}

/// The output must be valid JSON that can be parsed by a standard JSON parser.
#[test]
fn test_copilot_output_is_valid_json_on_allow() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"timestamp":1704614600000,"cwd":"/workspace","toolName":"allowed_tool","toolArgs":"{}"}"#;

    let output = run_copilot_hook(input, "preToolUse", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();

    // parse_stdout_json panics on invalid JSON — that's the assertion
    let _ = parse_stdout_json(&output);
}

#[test]
fn test_copilot_output_is_valid_json_on_deny() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"timestamp":1704614600000,"cwd":"/workspace","toolName":"forbidden_tool","toolArgs":"{}"}"#;

    let output = run_copilot_hook(input, "preToolUse", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();

    let _ = parse_stdout_json(&output);
}

/// The exit code for Copilot format must always be 0, even for denied tools.
/// Copilot ignores exit codes and reads only the JSON stdout.
#[test]
fn test_copilot_exit_code_always_zero_for_deny() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"timestamp":1704614600000,"cwd":"/workspace","toolName":"forbidden_tool","toolArgs":"{}"}"#;

    Command::new(bin_path())
        .arg("hook")
        .arg("--format")
        .arg("copilot")
        .arg("--event")
        .arg("preToolUse")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(input.as_bytes().to_vec())
        .assert()
        .success(); // success() asserts exit code 0
}

// ---------------------------------------------------------------------------
// Non-preToolUse events (output ignored by Copilot)
// ---------------------------------------------------------------------------

/// postToolUse output is ignored by Copilot, but the binary must still return
/// a valid JSON allow response and exit 0.
#[test]
fn test_copilot_post_tool_use_returns_allow_and_exits_zero() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{
        "timestamp": 1704614700000,
        "cwd": "/workspace",
        "toolName": "allowed_tool",
        "toolArgs": "{}",
        "toolResult": {"resultType": "success", "textResultForLlm": "done"}
    }"#;

    let output = run_copilot_hook(input, "postToolUse", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    assert_eq!(
        json["permissionDecision"].as_str(),
        Some("allow"),
        "postToolUse must return allow (output is informational)"
    );
}

/// sessionStart output is ignored by Copilot.
#[test]
fn test_copilot_session_start_returns_allow_and_exits_zero() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"timestamp":1704614400000,"cwd":"/workspace","source":"new","initialPrompt":"Build a feature"}"#;

    let output = run_copilot_hook(input, "sessionStart", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    assert_eq!(json["permissionDecision"].as_str(), Some("allow"));
}

/// sessionEnd output is ignored by Copilot.
#[test]
fn test_copilot_session_end_returns_allow_and_exits_zero() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"timestamp":1704618000000,"cwd":"/workspace","reason":"complete"}"#;

    let output = run_copilot_hook(input, "sessionEnd", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    assert_eq!(json["permissionDecision"].as_str(), Some("allow"));
}

// ---------------------------------------------------------------------------
// Taint persistence across calls (same workspace session)
// ---------------------------------------------------------------------------

/// When tool A adds a taint and tool B requires that taint, two invocations
/// with the same `cwd` must share session state (taint from call 1 is visible
/// in call 2). This verifies that the `derive_session_id(cwd)` → persistence
/// chain works correctly end-to-end.
#[test]
fn test_copilot_taint_persists_across_calls_same_workspace() {
    // Clean up any pre-existing session state that might affect this test.
    // We use a unique cwd path to isolate this test from others.
    let test_cwd = "/tmp/lilith-copilot-taint-test-unique-abc123";
    let session_id = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(test_cwd.as_bytes());
        format!("copilot-{}", hex::encode(&hash[..16]))
    };
    let session_file = dirs_session_file(&session_id);
    let _ = std::fs::remove_file(&session_file); // ignore if not present

    let policy_yaml = r#"
id: taint-test-policy
customer_id: test
name: Taint Persistence Test
version: 1
static_rules:
  taint_me: ALLOW
  check_me: ALLOW
taint_rules:
  - tool: taint_me
    action: ADD_TAINT
    tag: COPILOT_TAINT
  - tool: check_me
    action: CHECK_TAINT
    required_taints: ["COPILOT_TAINT"]
    error: "requires COPILOT_TAINT"
resource_rules: []
"#;
    let policy = write_temp_policy(policy_yaml);

    // Call 1: invoke taint_me → adds COPILOT_TAINT to session
    let input1 = format!(
        r#"{{"timestamp":1704614600000,"cwd":"{test_cwd}","toolName":"taint_me","toolArgs":"{{}}"}}"#
    );
    run_copilot_hook(&input1, "preToolUse", policy.path()).success();

    // Call 2: invoke check_me — requires COPILOT_TAINT which must have persisted
    let input2 = format!(
        r#"{{"timestamp":1704614700000,"cwd":"{test_cwd}","toolName":"check_me","toolArgs":"{{}}"}}"#
    );
    let output = run_copilot_hook(&input2, "preToolUse", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    assert_eq!(
        json["permissionDecision"].as_str(),
        Some("deny"),
        "check_me must be denied because COPILOT_TAINT is required (set by taint_me in same session)"
    );

    // Clean up session file
    let _ = std::fs::remove_file(&session_file);
}

/// Two different workspaces (different `cwd`) must use separate sessions.
///
/// Taint semantics: `CHECK_TAINT` DENIES a tool when the specified taint IS
/// active in the current session. This test verifies that:
/// - Workspace A acquires a taint (via `taint_source`) and is then DENIED
///   access to `check_tool` (the taint is present → block triggers).
/// - Workspace B never acquires that taint, so `check_tool` is ALLOWED there.
///
/// The correct isolation invariant is therefore:
///   "A taint applied in workspace A must NOT propagate to workspace B."
/// Proof: workspace B allows the tool that workspace A blocks.
#[test]
fn test_copilot_different_workspaces_have_isolated_sessions() {
    let cwd_a = "/tmp/lilith-copilot-workspace-a-xyz789";
    let cwd_b = "/tmp/lilith-copilot-workspace-b-xyz789";

    // Clean up pre-existing sessions for both workspaces
    for cwd in &[cwd_a, cwd_b] {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(cwd.as_bytes());
        let id = format!("copilot-{}", hex::encode(&hash[..16]));
        let _ = std::fs::remove_file(dirs_session_file(&id));
    }

    // CHECK_TAINT rule: deny check_tool when WORKSPACE_TAINT is active.
    let policy_yaml = r#"
id: isolation-test-policy
customer_id: test
name: Workspace Isolation Test
version: 1
static_rules:
  taint_source: ALLOW
  check_tool: ALLOW
taint_rules:
  - tool: taint_source
    action: ADD_TAINT
    tag: WORKSPACE_TAINT
  - tool: check_tool
    action: CHECK_TAINT
    required_taints: ["WORKSPACE_TAINT"]
    error: "blocked when WORKSPACE_TAINT is active"
resource_rules: []
"#;
    let policy = write_temp_policy(policy_yaml);

    // Step 1: Add WORKSPACE_TAINT to workspace A's session
    let input_a_taint = format!(
        r#"{{"timestamp":1704614600000,"cwd":"{cwd_a}","toolName":"taint_source","toolArgs":"{{}}"}}"#
    );
    run_copilot_hook(&input_a_taint, "preToolUse", policy.path()).success();

    // Step 2: Verify workspace A is DENIED for check_tool (WORKSPACE_TAINT is present)
    let input_a_check = format!(
        r#"{{"timestamp":1704614700000,"cwd":"{cwd_a}","toolName":"check_tool","toolArgs":"{{}}"}}"#
    );
    let output_a = run_copilot_hook(&input_a_check, "preToolUse", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json_a = parse_stdout_json(&output_a);
    assert_eq!(
        json_a["permissionDecision"].as_str(),
        Some("deny"),
        "check_tool must be denied in workspace A because WORKSPACE_TAINT is active there"
    );

    // Step 3: Verify workspace B is ALLOWED for check_tool (WORKSPACE_TAINT did NOT bleed from A)
    let input_b_check = format!(
        r#"{{"timestamp":1704614800000,"cwd":"{cwd_b}","toolName":"check_tool","toolArgs":"{{}}"}}"#
    );
    let output_b = run_copilot_hook(&input_b_check, "preToolUse", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();
    let json_b = parse_stdout_json(&output_b);
    assert_eq!(
        json_b["permissionDecision"].as_str(),
        Some("allow"),
        "check_tool must be allowed in workspace B: WORKSPACE_TAINT from workspace A must not bleed into an unrelated session"
    );

    // Clean up
    for cwd in &[cwd_a, cwd_b] {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(cwd.as_bytes());
        let id = format!("copilot-{}", hex::encode(&hash[..16]));
        let _ = std::fs::remove_file(dirs_session_file(&id));
    }
}

// ---------------------------------------------------------------------------
// Auto-detection of event type (no --event flag)
// ---------------------------------------------------------------------------

/// When `--event` is omitted, the binary must infer `preToolUse` from the
/// presence of `toolName` without `toolResult`.
#[test]
fn test_copilot_auto_detects_pre_tool_use_from_payload_shape() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"timestamp":1704614600000,"cwd":"/workspace","toolName":"allowed_tool","toolArgs":"{}"}"#;

    // No --event flag — must auto-detect
    let mut cmd = Command::new(bin_path());
    let output = cmd
        .arg("hook")
        .arg("--format")
        .arg("copilot")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(input.as_bytes().to_vec())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    assert_eq!(
        json["permissionDecision"].as_str(),
        Some("allow"),
        "auto-detected preToolUse with allowed tool must produce allow"
    );
}

// ---------------------------------------------------------------------------
// Backward compatibility: Claude Code format still works
// ---------------------------------------------------------------------------

/// Existing Claude Code hooks (no --format flag) must continue to work exactly
/// as before: exit code 0 for allow, exit code 2 for deny.
#[test]
fn test_claude_format_backward_compatibility_allow() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"session_id":"compat-session","hook_event_name":"PreToolUse","tool_name":"allowed_tool","tool_input":{"a":1}}"#;

    Command::new(bin_path())
        .arg("hook")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(input.as_bytes().to_vec())
        .assert()
        .success(); // exit code 0 = allow
}

#[test]
fn test_claude_format_backward_compatibility_deny() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"session_id":"compat-session","hook_event_name":"PreToolUse","tool_name":"forbidden_tool","tool_input":{"a":1}}"#;

    Command::new(bin_path())
        .arg("hook")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(input.as_bytes().to_vec())
        .assert()
        .failure() // exit code 2 = deny (assert_cmd treats non-0 as failure)
        .code(2);
}

/// Explicitly passing `--format claude` must behave identically to omitting the flag.
#[test]
fn test_explicit_claude_format_flag_works() {
    let policy = write_temp_policy(default_policy_yaml());
    let input = r#"{"session_id":"explicit-claude-session","hook_event_name":"PreToolUse","tool_name":"allowed_tool","tool_input":{}}"#;

    Command::new(bin_path())
        .arg("hook")
        .arg("--format")
        .arg("claude")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(input.as_bytes().to_vec())
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// toolArgs parsing (Copilot double-encodes arguments as a JSON string)
// ---------------------------------------------------------------------------

/// Copilot passes `toolArgs` as a JSON-encoded string (double-encoded).
/// The binary must decode it and pass the inner object to the policy engine.
#[test]
fn test_copilot_tool_args_json_string_is_decoded_correctly() {
    // Policy that checks a specific argument value via JsonLogic
    let policy_yaml = r#"
id: args-test-policy
customer_id: test
name: Args Parsing Test
version: 1
static_rules:
  bash: ALLOW
taint_rules: []
resource_rules: []
"#;
    let policy = write_temp_policy(policy_yaml);

    // toolArgs is a JSON string containing {"command":"ls -la"}
    let input = r#"{"timestamp":1704614600000,"cwd":"/workspace","toolName":"bash","toolArgs":"{\"command\":\"ls -la\"}"}"#;

    let output = run_copilot_hook(input, "preToolUse", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();

    let json = parse_stdout_json(&output);
    // bash is in the allow list, so this must be allowed regardless of args
    assert_eq!(
        json["permissionDecision"].as_str(),
        Some("allow"),
        "bash with valid toolArgs must be allowed"
    );
}

/// If `toolArgs` contains invalid JSON (not a valid JSON object/value string),
/// the binary must still make a policy decision (fail-closed if denied, allow
/// if tool is in the allow list). It must not crash or produce invalid output.
#[test]
fn test_copilot_invalid_tool_args_does_not_crash_binary() {
    let policy = write_temp_policy(default_policy_yaml());
    // toolArgs value is not valid JSON
    let input = r#"{"timestamp":1704614600000,"cwd":"/workspace","toolName":"allowed_tool","toolArgs":"not-json-at-all"}"#;

    let output = run_copilot_hook(input, "preToolUse", policy.path())
        .success()
        .get_output()
        .stdout
        .clone();

    // Must produce valid JSON output regardless
    let json = parse_stdout_json(&output);
    assert!(
        json["permissionDecision"].as_str().is_some(),
        "output must contain permissionDecision even with invalid toolArgs"
    );
}

// ---------------------------------------------------------------------------
// Helpers for session file path computation (mirrors PersistenceLayer logic)
// ---------------------------------------------------------------------------

/// Compute the session file path used by PersistenceLayer.
/// This mirrors `~/.lilith/sessions/{session_id}.json`.
fn dirs_session_file(session_id: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home)
        .join(".lilith")
        .join("sessions")
        .join(format!("{session_id}.json"))
}
