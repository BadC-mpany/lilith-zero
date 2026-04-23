//! Integration tests for the `validate`, `audit`, and `pin` subcommands.
//!
//! These tests invoke the real binary and assert on exit codes and stdout,
//! providing coverage for operator-facing commands that have no other tests.

#![cfg(not(miri))]

use assert_cmd::Command;
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lilith-zero"))
}

fn write_temp_file(content: &str, suffix: &str) -> NamedTempFile {
    let mut f = tempfile::Builder::new()
        .suffix(suffix)
        .tempfile()
        .expect("temp file");
    f.write_all(content.as_bytes()).expect("write");
    f
}

// ---------------------------------------------------------------------------
// validate subcommand
// ---------------------------------------------------------------------------

const VALID_POLICY: &str = r#"
id: test-validate
customer_id: test
name: Validate Test Policy
version: 1
static_rules:
  allowed_tool: ALLOW
  forbidden_tool: DENY
taint_rules: []
resource_rules: []
"#;

const INVALID_POLICY_YAML: &str = "this: {is: not: valid: yaml: [}";

const UNKNOWN_FIELDS_POLICY: &str = r#"
id: test-warnings
customer_id: test
name: Warnings Policy
version: 1
static_rules: {}
taint_rules: []
resource_rules: []
"#;

/// A valid policy YAML exits 0 and prints "OK".
#[test]
fn test_validate_valid_policy_exits_0() {
    let f = write_temp_file(VALID_POLICY, ".yaml");
    Command::new(bin_path())
        .arg("validate")
        .arg(f.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("OK"));
}

/// Malformed YAML exits non-zero (structural parse error).
#[test]
fn test_validate_malformed_yaml_exits_nonzero() {
    let f = write_temp_file(INVALID_POLICY_YAML, ".yaml");
    Command::new(bin_path())
        .arg("validate")
        .arg(f.path())
        .assert()
        .failure();
}

/// A missing policy file exits non-zero.
#[test]
fn test_validate_missing_file_exits_nonzero() {
    Command::new(bin_path())
        .arg("validate")
        .arg("/tmp/lilith-test-policy-does-not-exist-12345.yaml")
        .assert()
        .failure();
}

/// A policy with no rules is structurally valid but produces warnings — exits 0.
#[test]
fn test_validate_empty_rules_exits_0_with_warnings() {
    let f = write_temp_file(UNKNOWN_FIELDS_POLICY, ".yaml");
    Command::new(bin_path())
        .arg("validate")
        .arg(f.path())
        .assert()
        .success();
}

/// `validate` output must contain the policy name on success.
#[test]
fn test_validate_output_includes_policy_name() {
    let f = write_temp_file(VALID_POLICY, ".yaml");
    Command::new(bin_path())
        .arg("validate")
        .arg(f.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("Validate Test Policy"));
}

// ---------------------------------------------------------------------------
// audit subcommand
// ---------------------------------------------------------------------------

/// A well-formed JSONL audit log with a valid entry exits 0 and prints summary.
#[test]
fn test_audit_valid_log_exits_0() {
    // Minimal valid audit entry structure (no actual HMAC verification without session key).
    let log = r#"{"signature":"dGVzdA==","payload":"{\"session_id\":\"s1\",\"timestamp\":1000,\"event_type\":\"Decision\",\"details\":{\"decision\":\"ALLOW\",\"tool_name\":\"read_file\"}}"}"#;
    let f = write_temp_file(&format!("{log}\n"), ".jsonl");
    Command::new(bin_path())
        .arg("audit")
        .arg(f.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("Entries"));
}

/// A log file with all corrupt lines exits non-zero.
#[test]
fn test_audit_all_corrupt_entries_exits_nonzero() {
    let f = write_temp_file("this is not json at all\nalso not json\n", ".jsonl");
    Command::new(bin_path())
        .arg("audit")
        .arg(f.path())
        .assert()
        .failure();
}

/// A missing log file exits non-zero.
#[test]
fn test_audit_missing_file_exits_nonzero() {
    Command::new(bin_path())
        .arg("audit")
        .arg("/tmp/lilith-test-audit-does-not-exist-12345.jsonl")
        .assert()
        .failure();
}

/// `--verbose` flag prints raw payloads in addition to the summary.
#[test]
fn test_audit_verbose_flag_prints_payload() {
    let log = r#"{"signature":"dGVzdA==","payload":"{\"session_id\":\"s1\",\"timestamp\":1000,\"event_type\":\"Decision\",\"details\":{\"decision\":\"ALLOW\",\"tool_name\":\"read_file\"}}"}"#;
    let f = write_temp_file(&format!("{log}\n"), ".jsonl");
    Command::new(bin_path())
        .arg("audit")
        .arg("--verbose")
        .arg(f.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("session_id"));
}

/// An empty log file exits 0 (zero entries is not an error).
#[test]
fn test_audit_empty_log_exits_0() {
    let f = write_temp_file("", ".jsonl");
    Command::new(bin_path())
        .arg("audit")
        .arg(f.path())
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// pin subcommand
// ---------------------------------------------------------------------------

const VALID_PIN_STORE: &str = r#"[
  {"name": "read_file", "digest": "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"},
  {"name": "run_terminal", "digest": "def456abc123def456abc123def456abc123def456abc123def456abc123def4"}
]"#;

/// `pin show` on a valid pin file exits 0 and prints the tool names.
#[test]
fn test_pin_show_valid_file_exits_0() {
    let f = write_temp_file(VALID_PIN_STORE, ".json");
    Command::new(bin_path())
        .arg("pin")
        .arg("show")
        .arg("--pin-file")
        .arg(f.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("read_file"))
        .stdout(predicates::str::contains("run_terminal"));
}

/// `pin show` on a missing file exits non-zero.
#[test]
fn test_pin_show_missing_file_exits_nonzero() {
    Command::new(bin_path())
        .arg("pin")
        .arg("show")
        .arg("--pin-file")
        .arg("/tmp/lilith-test-pins-does-not-exist-12345.json")
        .assert()
        .failure();
}

/// `pin reset` on an existing file removes it and exits 0.
#[test]
fn test_pin_reset_existing_file_exits_0() {
    let f = write_temp_file(VALID_PIN_STORE, ".json");
    let path = f.path().to_path_buf();
    // Keep a copy of the path before `f` is consumed.
    Command::new(bin_path())
        .arg("pin")
        .arg("reset")
        .arg("--pin-file")
        .arg(&path)
        .assert()
        .success()
        .stdout(predicates::str::contains("reset"));
    assert!(!path.exists(), "pin file must be deleted after reset");
}

/// `pin reset` on a non-existent file exits 0 (idempotent).
#[test]
fn test_pin_reset_nonexistent_file_exits_0() {
    Command::new(bin_path())
        .arg("pin")
        .arg("reset")
        .arg("--pin-file")
        .arg("/tmp/lilith-test-pins-reset-nonexistent-12345.json")
        .assert()
        .success();
}
