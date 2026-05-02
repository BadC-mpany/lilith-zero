// Copyright 2026 BadCompany
// Red-team security verification suite for Lilith-Zero

use lilith_zero::engine_core::path_utils::extract_and_canonicalize_paths;
use serde_json::json;

#[test]
fn test_exploit_toctou_path_mutation() {
    // Attack: Use a path traversal string that lexical_canonicalize will "clean"
    // but the tool server would normally interpret as sensitive.
    let mut payload = json!({
        "path": "../../etc/shadow"
    });

    // Verification: Lilith-Zero MUST mutate the payload so the tool never sees the original string.
    let paths = extract_and_canonicalize_paths(&mut payload);

    assert!(paths.contains(&"etc/shadow".to_string()));
    assert_eq!(payload["path"], "etc/shadow");
    assert!(!payload["path"].as_str().unwrap().contains(".."));
}

#[test]
fn test_exploit_key_based_bypass() {
    // Attack: Hide the path in a JSON key to bypass value-only scanners.
    let mut payload = json!({
        "../../etc/passwd": "some_value"
    });

    let paths = extract_and_canonicalize_paths(&mut payload);

    // Verification: The key itself must be canonicalized and identified as a path.
    assert!(paths.contains(&"etc/passwd".to_string()));

    // The payload must be mutated to use the clean key.
    let obj = payload.as_object().unwrap();
    assert!(obj.contains_key("etc/passwd"));
    assert!(!obj.contains_key("../../etc/passwd"));
}

#[test]
fn test_nested_toctou_mutation() {
    let mut payload = json!({
        "deeply": {
            "nested": [
                {"file": "file:///tmp/./../etc/hosts"},
                "../../var/log/syslog"
            ]
        }
    });

    let _ = extract_and_canonicalize_paths(&mut payload);

    let nested = &payload["deeply"]["nested"];
    assert_eq!(nested[0]["file"], "/etc/hosts");
    assert_eq!(nested[1], "var/log/syslog");
}
