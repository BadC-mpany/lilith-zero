// Unit tests for pattern matcher

use sentinel_interceptor::core::models::HistoryEntry;
use sentinel_interceptor::engine::pattern_matcher::PatternMatcher;
use serde_json::json;
use std::collections::HashSet;

#[test]
fn test_sequence_pattern_simple() {
    let history = vec![HistoryEntry {
        tool: "read_file".to_string(),
        classes: vec!["SENSITIVE_READ".to_string()],
        timestamp: 1.0,
    }];

    let pattern = json!({
        "type": "sequence",
        "steps": [
            {"class": "SENSITIVE_READ"},
            {"class": "CONSEQUENTIAL_WRITE"}
        ],
        "max_distance": null
    });

    let current_taints = HashSet::new();
    let result = PatternMatcher::evaluate_pattern(
        &pattern,
        &history,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &current_taints,
    )
    .unwrap();

    assert!(result, "Sequence pattern should match");
}

#[test]
fn test_sequence_pattern_no_match() {
    let history = vec![HistoryEntry {
        tool: "read_file".to_string(),
        classes: vec!["SENSITIVE_READ".to_string()],
        timestamp: 1.0,
    }];

    let pattern = json!({
        "type": "sequence",
        "steps": [
            {"class": "SAFE_READ"},
            {"class": "CONSEQUENTIAL_WRITE"}
        ],
        "max_distance": null
    });

    let current_taints = HashSet::new();
    let result = PatternMatcher::evaluate_pattern(
        &pattern,
        &history,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &current_taints,
    )
    .unwrap();

    assert!(!result, "Sequence pattern should not match");
}

#[test]
fn test_sequence_pattern_by_tool_name() {
    let history = vec![HistoryEntry {
        tool: "read_file".to_string(),
        classes: vec!["SENSITIVE_READ".to_string()],
        timestamp: 1.0,
    }];

    let pattern = json!({
        "type": "sequence",
        "steps": [
            {"tool": "read_file"},
            {"tool": "web_search"}
        ],
        "max_distance": null
    });

    let current_taints = HashSet::new();
    let result = PatternMatcher::evaluate_pattern(
        &pattern,
        &history,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &current_taints,
    )
    .unwrap();

    assert!(result, "Sequence pattern by tool name should match");
}

#[test]
fn test_sequence_pattern_max_distance() {
    let history = vec![
        HistoryEntry {
            tool: "read_file".to_string(),
            classes: vec!["SENSITIVE_READ".to_string()],
            timestamp: 1.0,
        },
        HistoryEntry {
            tool: "other_tool".to_string(),
            classes: vec!["SAFE_READ".to_string()],
            timestamp: 2.0,
        },
        HistoryEntry {
            tool: "another_tool".to_string(),
            classes: vec!["SAFE_READ".to_string()],
            timestamp: 3.0,
        },
    ];

    // Pattern with max_distance=1 should not match (distance is 3)
    let pattern = json!({
        "type": "sequence",
        "steps": [
            {"class": "SENSITIVE_READ"},
            {"class": "CONSEQUENTIAL_WRITE"}
        ],
        "max_distance": 1
    });

    let current_taints = HashSet::new();
    let result = PatternMatcher::evaluate_pattern(
        &pattern,
        &history,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &current_taints,
    )
    .unwrap();

    assert!(!result, "Sequence pattern should not match due to max_distance");
}

#[test]
fn test_logic_pattern_and() {
    let history = vec![HistoryEntry {
        tool: "read_file".to_string(),
        classes: vec!["SENSITIVE_READ".to_string()],
        timestamp: 1.0,
    }];

    let pattern = json!({
        "type": "logic",
        "condition": {
            "AND": [
                {"session_has_class": "SENSITIVE_READ"},
                {"current_tool_class": "HUMAN_VERIFY"}
            ]
        }
    });

    let current_taints = HashSet::new();
    let result = PatternMatcher::evaluate_pattern(
        &pattern,
        &history,
        "delete_db",
        &["HUMAN_VERIFY".to_string()],
        &current_taints,
    )
    .unwrap();

    assert!(result, "Logic pattern with AND should match");
}

#[test]
fn test_logic_pattern_and_fails() {
    let history = vec![HistoryEntry {
        tool: "read_file".to_string(),
        classes: vec!["SENSITIVE_READ".to_string()],
        timestamp: 1.0,
    }];

    let pattern = json!({
        "type": "logic",
        "condition": {
            "AND": [
                {"session_has_class": "SENSITIVE_READ"},
                {"current_tool_class": "SAFE_READ"}  // Current tool doesn't have this class
            ]
        }
    });

    let current_taints = HashSet::new();
    let result = PatternMatcher::evaluate_pattern(
        &pattern,
        &history,
        "delete_db",
        &["HUMAN_VERIFY".to_string()],
        &current_taints,
    )
    .unwrap();

    assert!(!result, "Logic pattern with AND should fail");
}

#[test]
fn test_logic_pattern_or() {
    let history = vec![];

    let pattern = json!({
        "type": "logic",
        "condition": {
            "OR": [
                {"session_has_class": "SENSITIVE_READ"},  // False
                {"current_tool_class": "HUMAN_VERIFY"}    // True
            ]
        }
    });

    let current_taints = HashSet::new();
    let result = PatternMatcher::evaluate_pattern(
        &pattern,
        &history,
        "delete_db",
        &["HUMAN_VERIFY".to_string()],
        &current_taints,
    )
    .unwrap();

    assert!(result, "Logic pattern with OR should match");
}

#[test]
fn test_logic_pattern_not() {
    let history = vec![];

    let pattern = json!({
        "type": "logic",
        "condition": {
            "NOT": {
                "session_has_class": "SENSITIVE_READ"
            }
        }
    });

    let current_taints = HashSet::new();
    let result = PatternMatcher::evaluate_pattern(
        &pattern,
        &history,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &current_taints,
    )
    .unwrap();

    assert!(result, "Logic pattern with NOT should match (no sensitive read in history)");
}

#[test]
fn test_logic_pattern_current_tool() {
    let history = vec![];

    let pattern = json!({
        "type": "logic",
        "condition": {
            "current_tool": "web_search"
        }
    });

    let current_taints = HashSet::new();
    let result = PatternMatcher::evaluate_pattern(
        &pattern,
        &history,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &current_taints,
    )
    .unwrap();

    assert!(result, "Logic pattern matching current_tool should match");
}

#[test]
fn test_logic_pattern_session_has_taint() {
    let history = vec![];

    let pattern = json!({
        "type": "logic",
        "condition": {
            "session_has_taint": "sensitive_data"
        }
    });

    let mut current_taints = HashSet::new();
    current_taints.insert("sensitive_data".to_string());

    let result = PatternMatcher::evaluate_pattern(
        &pattern,
        &history,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &current_taints,
    )
    .unwrap();

    assert!(result, "Logic pattern matching session_has_taint should match");
}

#[test]
fn test_logic_pattern_complex_nested() {
    let history = vec![HistoryEntry {
        tool: "read_file".to_string(),
        classes: vec!["SENSITIVE_READ".to_string()],
        timestamp: 1.0,
    }];

    let pattern = json!({
        "type": "logic",
        "condition": {
            "AND": [
                {
                    "OR": [
                        {"session_has_class": "SENSITIVE_READ"},
                        {"session_has_class": "UNSAFE_EXECUTE"}
                    ]
                },
                {"current_tool_class": "HUMAN_VERIFY"}
            ]
        }
    });

    let current_taints = HashSet::new();
    let result = PatternMatcher::evaluate_pattern(
        &pattern,
        &history,
        "delete_db",
        &["HUMAN_VERIFY".to_string()],
        &current_taints,
    )
    .unwrap();

    assert!(result, "Complex nested logic pattern should match");
}

