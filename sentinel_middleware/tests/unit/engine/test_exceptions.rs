// Unit tests for rule exceptions

use sentinel_interceptor::core::models::{Decision, HistoryEntry, PolicyDefinition, PolicyRule, RuleException};
use sentinel_interceptor::engine::evaluator::PolicyEvaluator;
use serde_json::json;
use std::collections::{HashMap, HashSet};

#[tokio::test]
async fn test_exception_with_session_has_tool() {
    let mut static_rules = HashMap::new();
    static_rules.insert("send_email".to_string(), "ALLOW".to_string());
    static_rules.insert("anonymize_text".to_string(), "ALLOW".to_string());

    let exception = RuleException {
        condition: json!({
            "session_has_tool": "anonymize_text"
        }),
        reason: Some("Allow if data was anonymized".to_string()),
    };

    let taint_rule = PolicyRule {
        tool: None,
        tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
        action: "CHECK_TAINT".to_string(),
        tag: None,
        forbidden_tags: Some(vec!["sensitive_data".to_string()]),
        error: Some("Exfiltration blocked".to_string()),
        pattern: None,
        exceptions: Some(vec![exception]),
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    // History shows anonymize_text was used
    let history = vec![HistoryEntry {
        tool: "anonymize_text".to_string(),
        classes: vec!["SANITIZER".to_string()],
        timestamp: 1.0,
    }];

    let mut current_taints = HashSet::new();
    current_taints.insert("sensitive_data".to_string());

    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &history,
        &current_taints,
        &json!({"to": "user@example.com"}),
    )
    .await
    .unwrap();

    // Should be ALLOWED due to exception
    assert!(matches!(result, Decision::Allowed));
}

#[tokio::test]
async fn test_exception_with_tool_args_match_wildcard() {
    let mut static_rules = HashMap::new();
    static_rules.insert("send_email".to_string(), "ALLOW".to_string());

    let exception = RuleException {
        condition: json!({
            "AND": [
                {"session_has_tool": "anonymize_text"},
                {"tool_args_match": {"to": "internal_*"}}
            ]
        }),
        reason: Some("Allow internal sharing after anonymization".to_string()),
    };

    let taint_rule = PolicyRule {
        tool: None,
        tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
        action: "CHECK_TAINT".to_string(),
        tag: None,
        forbidden_tags: Some(vec!["sensitive_data".to_string()]),
        error: Some("Exfiltration blocked".to_string()),
        pattern: None,
        exceptions: Some(vec![exception]),
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    let history = vec![HistoryEntry {
        tool: "anonymize_text".to_string(),
        classes: vec!["SANITIZER".to_string()],
        timestamp: 1.0,
    }];

    let mut current_taints = HashSet::new();
    current_taints.insert("sensitive_data".to_string());

    // Test with internal destination (should pass)
    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &history,
        &current_taints,
        &json!({"to": "internal_team@company.com"}),
    )
    .await
    .unwrap();

    assert!(matches!(result, Decision::Allowed));

    // Test with external destination (should block)
    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &history,
        &current_taints,
        &json!({"to": "external@example.com"}),
    )
    .await
    .unwrap();

    match result {
        Decision::Denied { reason } => {
            assert!(reason.contains("Exfiltration blocked"));
        }
        _ => panic!("Expected Denied decision for external destination"),
    }
}

#[tokio::test]
async fn test_exception_with_and_condition() {
    let mut static_rules = HashMap::new();
    static_rules.insert("web_search".to_string(), "ALLOW".to_string());
    static_rules.insert("anonymize_text".to_string(), "ALLOW".to_string());

    let exception = RuleException {
        condition: json!({
            "AND": [
                {"session_has_tool": "anonymize_text"},
                {"current_tool_class": "CONSEQUENTIAL_WRITE"}
            ]
        }),
        reason: Some("Allow after anonymization".to_string()),
    };

    let taint_rule = PolicyRule {
        tool: None,
        tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
        action: "CHECK_TAINT".to_string(),
        tag: None,
        forbidden_tags: Some(vec!["sensitive_data".to_string()]),
        error: Some("Blocked".to_string()),
        pattern: None,
        exceptions: Some(vec![exception]),
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    let history = vec![HistoryEntry {
        tool: "anonymize_text".to_string(),
        classes: vec!["SANITIZER".to_string()],
        timestamp: 1.0,
    }];

    let mut current_taints = HashSet::new();
    current_taints.insert("sensitive_data".to_string());

    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &history,
        &current_taints,
        &json!({}),
    )
    .await
    .unwrap();

    // Both conditions satisfied, exception applies
    assert!(matches!(result, Decision::Allowed));
}

#[tokio::test]
async fn test_no_exception_applies() {
    let mut static_rules = HashMap::new();
    static_rules.insert("web_search".to_string(), "ALLOW".to_string());

    let exception = RuleException {
        condition: json!({
            "session_has_tool": "anonymize_text"
        }),
        reason: Some("Allow only after anonymization".to_string()),
    };

    let taint_rule = PolicyRule {
        tool: None,
        tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
        action: "CHECK_TAINT".to_string(),
        tag: None,
        forbidden_tags: Some(vec!["sensitive_data".to_string()]),
        error: Some("Exfiltration blocked".to_string()),
        pattern: None,
        exceptions: Some(vec![exception]),
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    // Empty history - anonymize_text NOT used
    let history = vec![];

    let mut current_taints = HashSet::new();
    current_taints.insert("sensitive_data".to_string());

    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &history,
        &current_taints,
        &json!({}),
    )
    .await
    .unwrap();

    // No exception applies, should be denied
    match result {
        Decision::Denied { reason } => {
            assert!(reason.contains("Exfiltration blocked"));
        }
        _ => panic!("Expected Denied decision"),
    }
}

#[tokio::test]
async fn test_multiple_exceptions_first_matches() {
    let mut static_rules = HashMap::new();
    static_rules.insert("send_email".to_string(), "ALLOW".to_string());
    static_rules.insert("anonymize_text".to_string(), "ALLOW".to_string());

    let exception1 = RuleException {
        condition: json!({
            "session_has_tool": "anonymize_text"
        }),
        reason: Some("Exception 1".to_string()),
    };

    let exception2 = RuleException {
        condition: json!({
            "session_has_tool": "some_other_tool"
        }),
        reason: Some("Exception 2".to_string()),
    };

    let taint_rule = PolicyRule {
        tool: None,
        tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
        action: "CHECK_TAINT".to_string(),
        tag: None,
        forbidden_tags: Some(vec!["sensitive_data".to_string()]),
        error: Some("Blocked".to_string()),
        pattern: None,
        exceptions: Some(vec![exception1, exception2]),
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    let history = vec![HistoryEntry {
        tool: "anonymize_text".to_string(),
        classes: vec!["SANITIZER".to_string()],
        timestamp: 1.0,
    }];

    let mut current_taints = HashSet::new();
    current_taints.insert("sensitive_data".to_string());

    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &history,
        &current_taints,
        &json!({}),
    )
    .await
    .unwrap();

    // First exception matches, should be allowed
    assert!(matches!(result, Decision::Allowed));
}

#[tokio::test]
async fn test_exception_with_exact_arg_match() {
    let mut static_rules = HashMap::new();
    static_rules.insert("send_email".to_string(), "ALLOW".to_string());

    let exception = RuleException {
        condition: json!({
            "tool_args_match": {"priority": "low"}
        }),
        reason: Some("Allow low priority emails".to_string()),
    };

    let taint_rule = PolicyRule {
        tool: None,
        tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
        action: "CHECK_TAINT".to_string(),
        tag: None,
        forbidden_tags: Some(vec!["sensitive_data".to_string()]),
        error: Some("Blocked".to_string()),
        pattern: None,
        exceptions: Some(vec![exception]),
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    let mut current_taints = HashSet::new();
    current_taints.insert("sensitive_data".to_string());

    // Test with matching priority
    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &[],
        &current_taints,
        &json!({"priority": "low", "to": "user@example.com"}),
    )
    .await
    .unwrap();

    assert!(matches!(result, Decision::Allowed));

    // Test with non-matching priority
    let result = PolicyEvaluator::evaluate_with_args(
        &policy,
        "send_email",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &[],
        &current_taints,
        &json!({"priority": "high"}),
    )
    .await
    .unwrap();

    assert!(matches!(result, Decision::Denied { .. }));
}
