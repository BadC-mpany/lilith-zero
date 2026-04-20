//! End-to-end integration tests for the OpenClaw hook adapter.
//!
//! These tests run the real `lilith-zero` binary with `--format openclaw` and
//! verify security-critical behaviour end-to-end.  Each test follows the
//! pattern: **Given** (setup) → **When** (binary invocation) → **Then** (exit code).
//!
//! # OpenClaw hook contract (proposed — openclaw/openclaw#60943)
//! - Exit code **0** → allow (tool invocation proceeds).
//! - Exit code **2** → deny (tool invocation is blocked).
//! - No JSON output is required; the exit code is authoritative.
//!
//! # Test naming convention
//! `test_openclaw_{scenario}_{expected_outcome}`

#![cfg(not(miri))]

use assert_cmd::Command;
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lilith-zero"))
}

fn write_temp_policy(yaml: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("failed to create temp policy file");
    f.write_all(yaml.as_bytes())
        .expect("failed to write policy");
    f
}

/// Session file path used by PersistenceLayer.
fn session_file(session_id: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home)
        .join(".lilith")
        .join("sessions")
        .join(format!("{session_id}.json"))
}

/// Run `lilith-zero hook --format openclaw` with the given JSON payload and policy.
fn run_openclaw(payload: &str, policy_path: &std::path::Path) -> assert_cmd::assert::Assert {
    Command::new(bin_path())
        .arg("hook")
        .arg("--format")
        .arg("openclaw")
        .arg("--policy")
        .arg(policy_path)
        .write_stdin(payload.as_bytes().to_vec())
        .assert()
}

/// Policy that allows `read_file` and `list_directory`, denies shell tools,
/// and blocks sensitive resource paths. All 4 new v0.3.0 features enabled.
fn openclaw_policy_yaml() -> String {
    r#"
id: openclaw-e2e-test
customer_id: test
name: OpenClaw E2E Test Policy
version: 1

pin_mode: audit
replay_window_secs: 300

rate_limit:
  max_calls_per_session: 3
  max_calls_per_minute: 60

static_rules:
  read_file:      ALLOW
  list_directory: ALLOW
  bash:           DENY
  shell:          DENY
  execute_command: DENY

taint_rules:
  - tool: read_file
    action: ADD_TAINT
    tag: ACCESS_PRIVATE

resource_rules:
  - uri_pattern: "/etc/*"
    action: BLOCK
  - uri_pattern: "~/.openclaw/*"
    action: BLOCK
  - uri_pattern: "*/.env"
    action: BLOCK
  - uri_pattern: "*/.env.*"
    action: BLOCK
  - uri_pattern: "~/.ssh/*"
    action: BLOCK
"#
    .to_string()
}

// ── Core allow / deny ─────────────────────────────────────────────────────────

/// A tool allowed by static rules must exit 0.
#[test]
fn test_openclaw_allowed_tool_exits_zero() {
    let policy = write_temp_policy(&openclaw_policy_yaml());
    let payload = r#"{"event":"preToolUse","sessionId":"oc-e2e-allow-1","toolName":"list_directory","toolInput":{"path":"/home/user/project"}}"#;
    let _ = session_file("oc-e2e-allow-1");
    let _ = std::fs::remove_file(session_file("oc-e2e-allow-1"));

    run_openclaw(payload, policy.path()).success();
}

/// A tool denied by static rules must exit 2.
#[test]
fn test_openclaw_denied_tool_exits_two() {
    let policy = write_temp_policy(&openclaw_policy_yaml());
    let payload = r#"{"event":"preToolUse","sessionId":"oc-e2e-deny-1","toolName":"bash","toolInput":{"cmd":"id"}}"#;
    let _ = std::fs::remove_file(session_file("oc-e2e-deny-1"));

    run_openclaw(payload, policy.path())
        .failure()
        .code(2);
}

/// An unknown tool must exit 2 (fail-closed — not in static_rules → DENY).
#[test]
fn test_openclaw_unknown_tool_fail_closed() {
    let policy = write_temp_policy(&openclaw_policy_yaml());
    let payload = r#"{"event":"preToolUse","sessionId":"oc-e2e-unknown-1","toolName":"unknown_mystery_tool","toolInput":{}}"#;
    let _ = std::fs::remove_file(session_file("oc-e2e-unknown-1"));

    run_openclaw(payload, policy.path())
        .failure()
        .code(2);
}

// ── Resource path arg enforcement ─────────────────────────────────────────────

/// A tool call with a path argument pointing to /etc/* must exit 2.
/// Covers: CVE-2026-33573, GHSA-cr8r-7g2h-6wr6.
#[test]
fn test_openclaw_path_traversal_etc_blocked() {
    let policy = write_temp_policy(&openclaw_policy_yaml());
    let payload = r#"{"event":"preToolUse","sessionId":"oc-e2e-path-etc","toolName":"read_file","toolInput":{"path":"/etc/passwd"}}"#;
    let _ = std::fs::remove_file(session_file("oc-e2e-path-etc"));

    run_openclaw(payload, policy.path())
        .failure()
        .code(2);
}

/// A tool call with a path argument ending in `.env` must exit 2.
/// Covers: GHSA-3qpv-xf3v-mm45, GHSA-qcj9-wwgw-6gm8.
#[test]
fn test_openclaw_dotenv_path_blocked() {
    let policy = write_temp_policy(&openclaw_policy_yaml());
    let payload = r#"{"event":"preToolUse","sessionId":"oc-e2e-path-env","toolName":"read_file","toolInput":{"path":"/home/user/project/.env"}}"#;
    let _ = std::fs::remove_file(session_file("oc-e2e-path-env"));

    run_openclaw(payload, policy.path())
        .failure()
        .code(2);
}

/// A `file:///etc/shadow` URI is normalised to `/etc/shadow` and then blocked.
/// Verifies the `file://` URI prefix-stripping in `evaluate_path_args`.
#[test]
fn test_openclaw_file_uri_prefix_stripped_and_blocked() {
    let policy = write_temp_policy(&openclaw_policy_yaml());
    let payload = r#"{"event":"preToolUse","sessionId":"oc-e2e-file-uri","toolName":"read_file","toolInput":{"path":"file:///etc/shadow"}}"#;
    let _ = std::fs::remove_file(session_file("oc-e2e-file-uri"));

    run_openclaw(payload, policy.path())
        .failure()
        .code(2);
}

/// A safe path under /home/ must exit 0 (no resource rule blocks it).
#[test]
fn test_openclaw_safe_home_path_allowed() {
    let policy = write_temp_policy(&openclaw_policy_yaml());
    let payload = r#"{"event":"preToolUse","sessionId":"oc-e2e-home-ok","toolName":"read_file","toolInput":{"path":"/home/user/report.txt"}}"#;
    let _ = std::fs::remove_file(session_file("oc-e2e-home-ok"));

    run_openclaw(payload, policy.path()).success();
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

/// After `max_calls_per_session: 3` tool calls the 4th must be denied.
/// Covers: CVE-2026-28478, CVE-2026-29609, OWASP Agentic 2026 #6.
#[test]
fn test_openclaw_rate_limit_session_cap() {
    let policy = write_temp_policy(&openclaw_policy_yaml());
    let session = "oc-e2e-ratelimit-session";
    let _ = std::fs::remove_file(session_file(session));

    let allowed_payload = |n: u32| {
        format!(
            r#"{{"event":"preToolUse","sessionId":"{session}","toolName":"list_directory","toolInput":{{"path":"/home/user/iter{n}"}}}}"#
        )
    };

    // Calls 1-3: must all be allowed (cap is 3).
    for i in 1..=3u32 {
        run_openclaw(&allowed_payload(i), policy.path()).success();
    }

    // Call 4: must be denied (exceeds max_calls_per_session: 3).
    run_openclaw(&allowed_payload(4), policy.path())
        .failure()
        .code(2);

    let _ = std::fs::remove_file(session_file(session));
}

// ── Error resilience ──────────────────────────────────────────────────────────

/// Empty stdin must exit 0 (fail-open for non-events — avoids blocking startup).
#[test]
fn test_openclaw_empty_stdin_exits_zero() {
    let policy = write_temp_policy(&openclaw_policy_yaml());
    Command::new(bin_path())
        .arg("hook")
        .arg("--format")
        .arg("openclaw")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(b"".to_vec())
        .assert()
        .success();
}

/// Malformed JSON must exit 2 (fail-closed — cannot parse = cannot trust).
#[test]
fn test_openclaw_malformed_json_exits_two() {
    let policy = write_temp_policy(&openclaw_policy_yaml());
    Command::new(bin_path())
        .arg("hook")
        .arg("--format")
        .arg("openclaw")
        .arg("--policy")
        .arg(policy.path())
        .write_stdin(b"{not valid json}".to_vec())
        .assert()
        .failure()
        .code(2);
}

/// Non-tool events (sessionStart, sessionEnd) must exit 0 — not blocked.
#[test]
fn test_openclaw_session_lifecycle_events_exit_zero() {
    let policy = write_temp_policy(&openclaw_policy_yaml());

    for event in ["sessionStart", "sessionEnd"] {
        let payload = format!(r#"{{"event":"{event}","sessionId":"oc-e2e-lifecycle"}}"#);
        Command::new(bin_path())
            .arg("hook")
            .arg("--format")
            .arg("openclaw")
            .arg("--policy")
            .arg(policy.path())
            .write_stdin(payload.into_bytes())
            .assert()
            .success();
    }
}

// ── Session isolation ─────────────────────────────────────────────────────────

/// Two concurrent sessions must not share state — each gets an independent
/// call count so session A's rate limit does not bleed into session B.
#[test]
fn test_openclaw_sessions_are_isolated() {
    let policy = write_temp_policy(&openclaw_policy_yaml());
    let session_a = "oc-e2e-iso-a";
    let session_b = "oc-e2e-iso-b";
    let _ = std::fs::remove_file(session_file(session_a));
    let _ = std::fs::remove_file(session_file(session_b));

    // Exhaust session A (3 calls).
    for i in 1..=3u32 {
        let p = format!(
            r#"{{"event":"preToolUse","sessionId":"{session_a}","toolName":"list_directory","toolInput":{{"path":"/home/user/a{i}"}}}}"#
        );
        run_openclaw(&p, policy.path()).success();
    }

    // Session A call 4 → denied.
    let p_a4 = format!(
        r#"{{"event":"preToolUse","sessionId":"{session_a}","toolName":"list_directory","toolInput":{{"path":"/home/user/a4"}}}}"#
    );
    run_openclaw(&p_a4, policy.path())
        .failure()
        .code(2);

    // Session B call 1 → still allowed (fresh session, independent counter).
    let p_b1 = format!(
        r#"{{"event":"preToolUse","sessionId":"{session_b}","toolName":"list_directory","toolInput":{{"path":"/home/user/b1"}}}}"#
    );
    run_openclaw(&p_b1, policy.path()).success();

    let _ = std::fs::remove_file(session_file(session_a));
    let _ = std::fs::remove_file(session_file(session_b));
}

// ── camelCase and snake_case alias handling ───────────────────────────────────

/// Both camelCase and snake_case field names in the payload must work.
#[test]
fn test_openclaw_snake_case_aliases_accepted() {
    let policy = write_temp_policy(&openclaw_policy_yaml());
    let _ = std::fs::remove_file(session_file("oc-e2e-snake"));

    // snake_case variant (as might appear in Python-generated payloads).
    let payload = r#"{"hook_event_name":"preToolUse","session_id":"oc-e2e-snake","tool_name":"list_directory","tool_input":{"path":"/home/user/docs"}}"#;
    run_openclaw(payload, policy.path()).success();
}
