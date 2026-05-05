//! Cedar-native tests for taint persistence across hook invocations.
//!
//! This test suite creates Cedar policies programmatically with proper "id" annotations
//! to test taint operations:
//! - Adding taints (via policies with @id("add_taint:TAG_NAME:..."))
//! - Checking taints (via policies that forbid when taints are present)
//! - Removing taints (via policies with @id("remove_taint:TAG_NAME:..."))
//! - Persisting taints across invocations (same session_id across processes)
//!
//! Note: Cedar policies don't natively support annotations in .cedar files.
//! Annotations are metadata that must be attached programmatically via PolicyId.
//! This is handled by creating a temporary YAML policy on-the-fly that gets compiled to Cedar.

#![cfg(not(miri))]

use assert_cmd::Command;
use std::io::Write;
use std::path::PathBuf;
use std::process::id as process_id;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lilith-zero"))
}

/// Create a temporary YAML policy with taint rules configured for the test.
/// This lets us define taint behavior in a native format that the SecurityCore understands.
fn create_taint_test_policy() -> NamedTempFile {
    let yaml = r#"
id: cedar-taint-test
customer_id: test
name: Cedar Taint Test Policy
version: 1
static_rules:
  taint_source_tool: ALLOW
  allowed_tool: ALLOW
  neutral_tool: ALLOW
  check_untrusted_tool: ALLOW
  remove_taint_tool: ALLOW
taint_rules:
  - tool: taint_source_tool
    action: ADD_TAINT
    tag: UNTRUSTED_DATA
  - tool: check_untrusted_tool
    action: CHECK_TAINT
    required_taints: ["UNTRUSTED_DATA"]
    error: "blocked by UNTRUSTED_DATA taint"
  - tool: remove_taint_tool
    action: REMOVE_TAINT
    tag: UNTRUSTED_DATA
resource_rules: []
"#;

    let mut f = NamedTempFile::new().expect("failed to create temp policy");
    f.write_all(yaml.as_bytes())
        .expect("failed to write policy");
    f
}

/// Run `lilith-zero hook` with the taint test policy and return the exit code assertion.
fn run_hook_with_taint_policy(
    session_id: &str,
    tool_name: &str,
    event_name: &str,
) -> assert_cmd::assert::Assert {
    let policy = create_taint_test_policy();

    let input = format!(
        r#"{{"session_id":"{}","hook_event_name":"{}","tool_name":"{}","tool_input":{{}}}}"#,
        session_id, event_name, tool_name
    );

    let mut cmd = Command::new(bin_path());
    cmd.arg("hook")
        .arg("--format")
        .arg("claude")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(input.as_bytes().to_vec());

    cmd.assert()
}

/// Cleanup session file after test.
fn cleanup_session(session_id: &str) {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let path = std::path::PathBuf::from(home)
        .join(".lilith")
        .join("sessions")
        .join(format!("{}.json", session_id));
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Unit Tests: Basic Cedar operations
// ---------------------------------------------------------------------------

/// Test that taint_source_tool is permitted (exit code 0).
/// This is a baseline test to verify the Cedar policy allows the tool.
#[test]
fn test_cedar_taint_source_tool_permitted() {
    let session_id = format!("cedar-baseline-{}", process_id());
    run_hook_with_taint_policy(&session_id, "taint_source_tool", "PreToolUse").code(0);
    cleanup_session(&session_id);
}

/// Test that allowed_tool is permitted (exit code 0).
/// Baseline: tool without any taint effects.
#[test]
fn test_cedar_allowed_tool_permitted() {
    let session_id = format!("cedar-neutral-{}", process_id());
    run_hook_with_taint_policy(&session_id, "allowed_tool", "PreToolUse").code(0);
    cleanup_session(&session_id);
}

/// Test that check_untrusted_tool is permitted when NO taint is present (exit code 0).
/// This verifies the CHECK_TAINT rule: forbid only when taint IS present.
#[test]
fn test_cedar_check_tool_allowed_without_taint() {
    let session_id = format!("cedar-no-taint-{}", process_id());

    // Single invocation: check_untrusted_tool should be allowed (no taint yet).
    run_hook_with_taint_policy(&session_id, "check_untrusted_tool", "PreToolUse").code(0);

    cleanup_session(&session_id);
}

/// Test that unknown tools are denied (exit code 2).
/// Baseline: Cedar default deny for tools not in the policy.
#[test]
fn test_cedar_unknown_tool_denied() {
    let session_id = format!("cedar-unknown-{}", process_id());
    run_hook_with_taint_policy(&session_id, "nonexistent_tool", "PreToolUse").code(2);
    cleanup_session(&session_id);
}

// ---------------------------------------------------------------------------
// Integration Tests: Taint persistence across invocations
// ---------------------------------------------------------------------------

/// Core test: Taint added in invocation 1 must block tool in invocation 2.
///
/// This is the canonical taint persistence test:
/// 1. Call taint_source_tool (adds UNTRUSTED_DATA taint) → expect allow (0)
/// 2. Call check_untrusted_tool in SAME session → expect deny (2)
///
/// This verifies the session state is being maintained and the taint is present.
#[test]
fn test_cedar_taint_persists_single_session() {
    let session_id = format!("cedar-persist-same-{}", process_id());

    // Invocation 1: Add taint (should succeed with exit 0).
    run_hook_with_taint_policy(&session_id, "taint_source_tool", "PreToolUse").code(0);

    // Invocation 2: Check for taint (should deny with exit 2 because taint is present).
    run_hook_with_taint_policy(&session_id, "check_untrusted_tool", "PreToolUse").code(2);

    cleanup_session(&session_id);
}

/// Taint must persist across separate invocations (different processes).
///
/// This tests the CORE persistence mechanism: taints saved to disk in process 1
/// must be loaded in process 2.
///
/// 1. Process 1: Call taint_source_tool → adds taint, saves to ~/.lilith/sessions/{session_id}.json
/// 2. Process 2: Call check_untrusted_tool → loads taint from disk, denies
#[test]
fn test_cedar_taint_persists_across_separate_invocations() {
    let session_id = format!("cedar-persist-cross-process-{}", process_id());

    // First invocation (Process 1): Add taint.
    run_hook_with_taint_policy(&session_id, "taint_source_tool", "PreToolUse").code(0);

    // Second invocation (Process 2): Load taint from disk and check it.
    // This is a NEW process, so it must deserialize the session state from disk.
    run_hook_with_taint_policy(&session_id, "check_untrusted_tool", "PreToolUse").code(2);

    cleanup_session(&session_id);
}

/// Sequence test: Add → Check (deny) → Remove → Check (allow).
///
/// This tests the full lifecycle:
/// 1. Add taint
/// 2. Verify taint blocks subsequent tools
/// 3. Remove taint
/// 4. Verify taint no longer blocks tools
#[test]
fn test_cedar_taint_lifecycle_full() {
    let session_id = format!("cedar-lifecycle-{}", process_id());

    // Step 1: Add taint.
    run_hook_with_taint_policy(&session_id, "taint_source_tool", "PreToolUse").code(0);

    // Step 2: Verify taint blocks check_untrusted_tool.
    run_hook_with_taint_policy(&session_id, "check_untrusted_tool", "PreToolUse").code(2);

    // Step 3: Remove taint.
    run_hook_with_taint_policy(&session_id, "remove_taint_tool", "PreToolUse").code(0);

    // Step 4: Verify taint no longer blocks check_untrusted_tool.
    run_hook_with_taint_policy(&session_id, "check_untrusted_tool", "PreToolUse").code(0);

    cleanup_session(&session_id);
}

/// Multiple taint additions: multiple taints can coexist.
/// (Note: This test uses only UNTRUSTED_DATA, but the infrastructure supports multiple.)
#[test]
fn test_cedar_multiple_taint_additions() {
    let session_id = format!("cedar-multi-{}", process_id());

    // Add taint once.
    run_hook_with_taint_policy(&session_id, "taint_source_tool", "PreToolUse").code(0);

    // Add taint again (idempotent: should still be blocked).
    run_hook_with_taint_policy(&session_id, "taint_source_tool", "PreToolUse").code(0);

    // Verify taint is still blocking.
    run_hook_with_taint_policy(&session_id, "check_untrusted_tool", "PreToolUse").code(2);

    // Remove taint once (should clear it completely).
    run_hook_with_taint_policy(&session_id, "remove_taint_tool", "PreToolUse").code(0);

    // Verify removal is complete.
    run_hook_with_taint_policy(&session_id, "check_untrusted_tool", "PreToolUse").code(0);

    cleanup_session(&session_id);
}

/// Cross-session isolation: Session A's taints must NOT affect Session B.
#[test]
fn test_cedar_taint_isolation_between_sessions() {
    let session_a = format!("cedar-session-a-{}", process_id());
    let session_b = format!("cedar-session-b-{}", process_id());

    // Session A: Add taint.
    run_hook_with_taint_policy(&session_a, "taint_source_tool", "PreToolUse").code(0);

    // Session A: Verify taint blocks.
    run_hook_with_taint_policy(&session_a, "check_untrusted_tool", "PreToolUse").code(2);

    // Session B: Check tool should be allowed (no taint in session B).
    run_hook_with_taint_policy(&session_b, "check_untrusted_tool", "PreToolUse").code(0);

    // Session B: Add its own taint.
    run_hook_with_taint_policy(&session_b, "taint_source_tool", "PreToolUse").code(0);

    // Session B: Now blocked.
    run_hook_with_taint_policy(&session_b, "check_untrusted_tool", "PreToolUse").code(2);

    // Session A: Still blocked (not affected by B).
    run_hook_with_taint_policy(&session_a, "check_untrusted_tool", "PreToolUse").code(2);

    cleanup_session(&session_a);
    cleanup_session(&session_b);
}

// ---------------------------------------------------------------------------
// Event type coverage
// ---------------------------------------------------------------------------

/// Taints persist across different tool names in same session.
#[test]
fn test_cedar_taint_with_different_tools() {
    let session_id = format!("cedar-different-tools-{}", process_id());

    // Call 1: taint_source_tool (adds taint).
    run_hook_with_taint_policy(&session_id, "taint_source_tool", "PreToolUse").code(0);

    // Call 2: neutral_tool (should be allowed, no taint check).
    run_hook_with_taint_policy(&session_id, "neutral_tool", "PreToolUse").code(0);

    // Call 3: check_untrusted_tool (should deny because taint was added).
    run_hook_with_taint_policy(&session_id, "check_untrusted_tool", "PreToolUse").code(2);

    cleanup_session(&session_id);
}
