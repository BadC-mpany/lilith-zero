//! Cedar taint persistence tests — two complementary paths:
//!
//! **Path A — YAML-compiled Cedar (hook --policy <yaml>)**
//! The `yaml_to_cedar` compiler sets PolicyIds directly as `"add_taint:TAG:..."`,
//! so taint extraction falls through to `policy_id.to_string()`. Tests here
//! verify the YAML → Cedar compilation path end-to-end.
//!
//! **Path B — Native Cedar files (hook --policy <file.cedar>)**
//! Cedar assigns auto-incremented PolicyIds (`policy0`, `policy1`, …).
//! Taint directives live in `@id("add_taint:TAG:...")` annotations and are read
//! via `get_policy_annotation(policy_id, "id")`. This is the path used in
//! production Copilot Studio deployments. Tests here cover the annotation lookup
//! that was the root cause of the taint persistence bug (fixed 2026-05-05).
//!
//! **Unit tests**
//! Direct verification that `get_policy_annotation` returns `@id` annotation
//! values correctly — the single most critical unit to keep covered given past
//! breakage.

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

/// Create a temporary YAML policy. Goes through yaml_to_cedar compilation.
fn create_yaml_taint_policy() -> NamedTempFile {
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
    let mut f = NamedTempFile::new().expect("temp file");
    f.write_all(yaml.as_bytes()).expect("write yaml");
    f
}

/// Run `lilith-zero hook` with the given policy file path.
fn run_hook(policy_path: &std::path::Path, session_id: &str, tool_name: &str) -> assert_cmd::assert::Assert {
    let input = format!(
        r#"{{"session_id":"{}","hook_event_name":"PreToolUse","tool_name":"{}","tool_input":{{}}}}"#,
        session_id, tool_name
    );
    Command::new(bin_path())
        .args(["hook", "--format", "claude", "--policy"])
        .arg(policy_path)
        .write_stdin(input.as_bytes().to_vec())
        .assert()
}

fn run_hook_yaml(session_id: &str, tool_name: &str) -> assert_cmd::assert::Assert {
    let policy = create_yaml_taint_policy();
    run_hook(policy.path(), session_id, tool_name)
}

fn run_hook_cedar(session_id: &str, tool_name: &str) -> assert_cmd::assert::Assert {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/taint_persistence.cedar");
    run_hook(&fixture, session_id, tool_name)
}

fn cleanup_session(session_id: &str) {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let path = PathBuf::from(home)
        .join(".lilith")
        .join("sessions")
        .join(format!("{}.json", session_id));
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Unit tests: get_policy_annotation returns @id annotation values
//
// This is the single most critical unit to cover — it was the root cause of
// the taint persistence bug. Cedar auto-assigns PolicyIds as "policy0", …;
// taint directives are encoded in @id annotations, not in the PolicyId.
// ---------------------------------------------------------------------------

#[cfg(feature = "webhook")]
mod annotation_unit_tests {
    use lilith_zero::engine::cedar_evaluator::CedarEvaluator;
    use std::str::FromStr;

    /// Verify that get_policy_annotation("id") returns the @id annotation value.
    /// This is the lookup that taint extraction depends on.
    #[test]
    fn test_get_policy_annotation_returns_id_value() {
        let policy_text = r#"
            @id("add_taint:UNTRUSTED_DATA:rule")
            permit(principal, action == Action::"tools/call", resource == Resource::"some_tool");
        "#;
        let ps = cedar_policy::PolicySet::from_str(policy_text).expect("valid cedar");
        let eval = CedarEvaluator::new(ps.clone());

        // The policy_id assigned by Cedar will be "policy0" (auto-increment).
        // We look up its @id annotation to get the taint directive.
        let policy_id = cedar_policy::PolicyId::from_str("policy0").expect("valid id");
        let annotation = eval.get_policy_annotation(&policy_id, "id");
        assert_eq!(
            annotation.as_deref(),
            Some("add_taint:UNTRUSTED_DATA:rule"),
            "get_policy_annotation must return the @id annotation value, not the auto-assigned PolicyId"
        );
    }

    /// Verify remove_taint @id annotation is also retrievable.
    #[test]
    fn test_get_policy_annotation_remove_taint() {
        let policy_text = r#"
            @id("remove_taint:UNTRUSTED_DATA:rule")
            permit(principal, action == Action::"tools/call", resource == Resource::"clean_tool");
        "#;
        let ps = cedar_policy::PolicySet::from_str(policy_text).expect("valid cedar");
        let eval = CedarEvaluator::new(ps);
        let policy_id = cedar_policy::PolicyId::from_str("policy0").expect("valid id");
        let annotation = eval.get_policy_annotation(&policy_id, "id");
        assert_eq!(annotation.as_deref(), Some("remove_taint:UNTRUSTED_DATA:rule"));
    }

    /// Verify policies WITHOUT @id return None (fallback to policy_id.to_string() applies).
    #[test]
    fn test_get_policy_annotation_no_id_returns_none() {
        let policy_text = r#"
            permit(principal, action == Action::"tools/call", resource == Resource::"plain_tool");
        "#;
        let ps = cedar_policy::PolicySet::from_str(policy_text).expect("valid cedar");
        let eval = CedarEvaluator::new(ps);
        let policy_id = cedar_policy::PolicyId::from_str("policy0").expect("valid id");
        let annotation = eval.get_policy_annotation(&policy_id, "id");
        assert_eq!(annotation, None, "policies without @id must return None");
    }
}

// ---------------------------------------------------------------------------
// Path A: YAML-compiled Cedar
// Tests the yaml_to_cedar → Cedar PolicySet path. PolicyIds are set directly
// as "add_taint:TAG:..." by the compiler so no annotation lookup is needed.
// ---------------------------------------------------------------------------

#[test]
fn test_yaml_taint_source_permitted() {
    let s = format!("yaml-baseline-{}", process_id());
    run_hook_yaml(&s, "taint_source_tool").code(0);
    cleanup_session(&s);
}

#[test]
fn test_yaml_allowed_tool_permitted() {
    let s = format!("yaml-neutral-{}", process_id());
    run_hook_yaml(&s, "allowed_tool").code(0);
    cleanup_session(&s);
}

#[test]
fn test_yaml_check_tool_allowed_without_taint() {
    let s = format!("yaml-no-taint-{}", process_id());
    run_hook_yaml(&s, "check_untrusted_tool").code(0);
    cleanup_session(&s);
}

#[test]
fn test_yaml_unknown_tool_denied() {
    let s = format!("yaml-unknown-{}", process_id());
    run_hook_yaml(&s, "nonexistent_tool").code(2);
    cleanup_session(&s);
}

#[test]
fn test_yaml_taint_persists_single_session() {
    let s = format!("yaml-persist-{}", process_id());
    run_hook_yaml(&s, "taint_source_tool").code(0);
    run_hook_yaml(&s, "check_untrusted_tool").code(2);
    cleanup_session(&s);
}

#[test]
fn test_yaml_taint_lifecycle_full() {
    let s = format!("yaml-lifecycle-{}", process_id());
    run_hook_yaml(&s, "taint_source_tool").code(0);
    run_hook_yaml(&s, "check_untrusted_tool").code(2);
    run_hook_yaml(&s, "remove_taint_tool").code(0);
    run_hook_yaml(&s, "check_untrusted_tool").code(0);
    cleanup_session(&s);
}

#[test]
fn test_yaml_taint_isolation_between_sessions() {
    let a = format!("yaml-session-a-{}", process_id());
    let b = format!("yaml-session-b-{}", process_id());
    run_hook_yaml(&a, "taint_source_tool").code(0);
    run_hook_yaml(&a, "check_untrusted_tool").code(2);
    run_hook_yaml(&b, "check_untrusted_tool").code(0);
    run_hook_yaml(&b, "taint_source_tool").code(0);
    run_hook_yaml(&b, "check_untrusted_tool").code(2);
    run_hook_yaml(&a, "check_untrusted_tool").code(2);
    cleanup_session(&a);
    cleanup_session(&b);
}

#[test]
fn test_yaml_multiple_taint_additions_idempotent() {
    let s = format!("yaml-multi-{}", process_id());
    run_hook_yaml(&s, "taint_source_tool").code(0);
    run_hook_yaml(&s, "taint_source_tool").code(0);
    run_hook_yaml(&s, "check_untrusted_tool").code(2);
    run_hook_yaml(&s, "remove_taint_tool").code(0);
    run_hook_yaml(&s, "check_untrusted_tool").code(0);
    cleanup_session(&s);
}

// ---------------------------------------------------------------------------
// Path B: Native Cedar files (the production path for Copilot Studio)
// Tests the @id annotation lookup in get_policy_annotation.
// PolicyIds are auto-assigned as "policy0", "policy1", …; taint directives
// are encoded in @id annotations. This path was the root cause of the bug.
// ---------------------------------------------------------------------------

#[test]
fn test_native_cedar_taint_source_permitted() {
    let s = format!("cedar-baseline-{}", process_id());
    run_hook_cedar(&s, "taint_source_tool").code(0);
    cleanup_session(&s);
}

#[test]
fn test_native_cedar_allowed_tool_permitted() {
    let s = format!("cedar-neutral-{}", process_id());
    run_hook_cedar(&s, "allowed_tool").code(0);
    cleanup_session(&s);
}

#[test]
fn test_native_cedar_check_tool_allowed_without_taint() {
    let s = format!("cedar-no-taint-{}", process_id());
    run_hook_cedar(&s, "check_untrusted_tool").code(0);
    cleanup_session(&s);
}

#[test]
fn test_native_cedar_unknown_tool_denied() {
    let s = format!("cedar-unknown-{}", process_id());
    run_hook_cedar(&s, "nonexistent_tool").code(2);
    cleanup_session(&s);
}

/// Regression test for the @id annotation taint extraction bug (2026-05-05).
/// Taint added via @id("add_taint:UNTRUSTED_DATA:rule") in a native .cedar file
/// must block check_untrusted_tool in the same session.
#[test]
fn test_native_cedar_taint_persists_single_session() {
    let s = format!("cedar-persist-{}", process_id());
    run_hook_cedar(&s, "taint_source_tool").code(0);
    run_hook_cedar(&s, "check_untrusted_tool").code(2);
    cleanup_session(&s);
}

#[test]
fn test_native_cedar_taint_lifecycle_full() {
    let s = format!("cedar-lifecycle-{}", process_id());
    run_hook_cedar(&s, "taint_source_tool").code(0);
    run_hook_cedar(&s, "check_untrusted_tool").code(2);
    run_hook_cedar(&s, "remove_taint_tool").code(0);
    run_hook_cedar(&s, "check_untrusted_tool").code(0);
    cleanup_session(&s);
}

#[test]
fn test_native_cedar_taint_isolation_between_sessions() {
    let a = format!("cedar-session-a-{}", process_id());
    let b = format!("cedar-session-b-{}", process_id());
    run_hook_cedar(&a, "taint_source_tool").code(0);
    run_hook_cedar(&a, "check_untrusted_tool").code(2);
    run_hook_cedar(&b, "check_untrusted_tool").code(0);
    cleanup_session(&a);
    cleanup_session(&b);
}
