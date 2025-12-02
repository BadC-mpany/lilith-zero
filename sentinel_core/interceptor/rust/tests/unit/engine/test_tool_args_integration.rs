// Integration test: Verify tool_args flow through entire evaluation pipeline

use sentinel_interceptor::core::models::{HistoryEntry, PolicyDefinition, PolicyRule};
use sentinel_interceptor::engine::evaluator::PolicyEvaluator;
use sentinel_interceptor::core::models::Decision;
use serde_json::json;
use std::collections::{HashMap, HashSet};

#[test]
fn test_tool_args_in_logic_pattern_blocks_matching_args() {
    let mut static_rules = HashMap::new();
    static_rules.insert("send_email".to_string(), "ALLOW".to_string());

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![PolicyRule {
            tool: Some("send_email".to_string()),
            tool_class: None,
            action: "BLOCK_CURRENT".to_string(),
            tag: None,
            forbidden_tags: None,
            error: Some("Blocked external email".to_string()),
            pattern: Some(json!({
                "type": "logic",
                "condition": {
                    "tool_args_match": {"to": "*@external.com"}
                }
            })),
            exceptions: None,
        }],
    };

    let current_taints = HashSet::new();
    let session_history = vec![];

    // Test 1: Matching args should block
    let tool_args = json!({"to": "user@external.com", "subject": "Test"});
    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &[],
        &session_history,
        &current_taints,
        &tool_args,
    )
    .unwrap();

    match result {
        Decision::Denied { reason } => {
            assert_eq!(reason, "Blocked external email");
        }
        _ => panic!("Expected Denied, got: {:?}", result),
    }

    // Test 2: Non-matching args should allow
    let tool_args = json!({"to": "user@company.com", "subject": "Test"});
    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &[],
        &session_history,
        &current_taints,
        &tool_args,
    )
    .unwrap();

    match result {
        Decision::Allowed => {}
        _ => panic!("Expected Allowed, got: {:?}", result),
    }
}

#[test]
fn test_tool_args_in_logic_pattern_with_complex_condition() {
    let mut static_rules = HashMap::new();
    static_rules.insert("send_email".to_string(), "ALLOW".to_string());
    static_rules.insert("read_file".to_string(), "ALLOW".to_string());

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![
            // Add taint when reading files
            PolicyRule {
                tool: Some("read_file".to_string()),
                tool_class: None,
                action: "ADD_TAINT".to_string(),
                tag: Some("sensitive_data".to_string()),
                forbidden_tags: None,
                error: None,
                pattern: None,
                exceptions: None,
            },
            // Block external email if session has sensitive_data taint
            PolicyRule {
                tool: Some("send_email".to_string()),
                tool_class: None,
                action: "BLOCK_CURRENT".to_string(),
                tag: None,
                forbidden_tags: None,
                error: Some("Cannot send sensitive data externally".to_string()),
                pattern: Some(json!({
                    "type": "logic",
                    "condition": {
                        "AND": [
                            {"session_has_taint": "sensitive_data"},
                            {"tool_args_match": {"to": "*@external.com"}}
                        ]
                    }
                })),
                exceptions: None,
            },
        ],
    };

    // Simulate a session history with a file read
    let session_history = vec![HistoryEntry {
        tool: "read_file".to_string(),
        classes: vec![],
        timestamp: 1000.0,
    }];

    let mut current_taints = HashSet::new();
    current_taints.insert("sensitive_data".to_string());

    // Test 1: External email with sensitive data taint should be blocked
    let tool_args = json!({"to": "user@external.com", "subject": "Test"});
    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &[],
        &session_history,
        &current_taints,
        &tool_args,
    )
    .unwrap();

    match result {
        Decision::Denied { reason } => {
            assert_eq!(reason, "Cannot send sensitive data externally");
        }
        _ => panic!("Expected Denied, got: {:?}", result),
    }

    // Test 2: Internal email with sensitive data taint should be allowed
    let tool_args = json!({"to": "user@company.com", "subject": "Test"});
    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &[],
        &session_history,
        &current_taints,
        &tool_args,
    )
    .unwrap();

    match result {
        Decision::Allowed => {}
        _ => panic!("Expected Allowed, got: {:?}", result),
    }

    // Test 3: External email WITHOUT taint should be allowed
    let no_taints = HashSet::new();
    let tool_args = json!({"to": "user@external.com", "subject": "Test"});
    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &[],
        &[],
        &no_taints,
        &tool_args,
    )
    .unwrap();

    match result {
        Decision::Allowed => {}
        _ => panic!("Expected Allowed, got: {:?}", result),
    }
}

#[test]
fn test_tool_args_in_exception_allows_bypass() {
    use sentinel_interceptor::core::models::RuleException;

    let mut static_rules = HashMap::new();
    static_rules.insert("send_email".to_string(), "ALLOW".to_string());

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![PolicyRule {
            tool: Some("send_email".to_string()),
            tool_class: None,
            action: "CHECK_TAINT".to_string(),
            tag: None,
            forbidden_tags: Some(vec!["sensitive_data".to_string()]),
            error: Some("Cannot send with sensitive data".to_string()),
            pattern: None,
            exceptions: Some(vec![RuleException {
                condition: json!({
                    "tool_args_match": {"to": "*@company.com"}
                }),
                reason: Some("Internal emails allowed".to_string()),
            }]),
        }],
    };

    let mut current_taints = HashSet::new();
    current_taints.insert("sensitive_data".to_string());
    let session_history = vec![];

    // Test 1: Internal email with sensitive taint should be allowed (exception)
    let tool_args = json!({"to": "user@company.com", "subject": "Test"});
    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &[],
        &session_history,
        &current_taints,
        &tool_args,
    )
    .unwrap();

    match result {
        Decision::Allowed => {}
        _ => panic!("Expected Allowed (exception), got: {:?}", result),
    }

    // Test 2: External email with sensitive taint should be blocked (no exception)
    let tool_args = json!({"to": "user@external.com", "subject": "Test"});
    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &[],
        &session_history,
        &current_taints,
        &tool_args,
    )
    .unwrap();

    match result {
        Decision::Denied { reason } => {
            assert_eq!(reason, "Cannot send with sensitive data");
        }
        _ => panic!("Expected Denied, got: {:?}", result),
    }
}

