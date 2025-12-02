// Unit tests for policy evaluator

use sentinel_interceptor::core::models::{Decision, HistoryEntry, PolicyDefinition, PolicyRule};
use sentinel_interceptor::engine::evaluator::PolicyEvaluator;
use std::collections::{HashMap, HashSet};

#[test]
fn test_static_rule_allow_no_taints() {
    let mut static_rules = HashMap::new();
    static_rules.insert("read_file".to_string(), "ALLOW".to_string());

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![],
    };

    let result = PolicyEvaluator::evaluate(
        &policy,
        "read_file",
        &[],
        &[],
        &HashSet::new(),
    )
    .unwrap();

    assert!(matches!(result, Decision::Allowed));
}

#[test]
fn test_static_rule_deny() {
    let mut static_rules = HashMap::new();
    static_rules.insert("delete_db".to_string(), "DENY".to_string());

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![],
    };

    let result = PolicyEvaluator::evaluate(
        &policy,
        "delete_db",
        &[],
        &[],
        &HashSet::new(),
    )
    .unwrap();

    match result {
        Decision::Denied { reason } => {
            assert!(reason.contains("delete_db"));
            assert!(reason.contains("forbidden"));
        }
        _ => panic!("Expected Denied decision"),
    }
}

#[test]
fn test_implicit_deny() {
    let static_rules = HashMap::new();

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![],
    };

    let result = PolicyEvaluator::evaluate(
        &policy,
        "unknown_tool",
        &[],
        &[],
        &HashSet::new(),
    )
    .unwrap();

    assert!(matches!(result, Decision::Denied { .. }));
}

#[test]
fn test_add_taint_by_tool_name() {
    let mut static_rules = HashMap::new();
    static_rules.insert("read_file".to_string(), "ALLOW".to_string());

    let taint_rule = PolicyRule {
        tool: Some("read_file".to_string()),
        tool_class: None,
        action: "ADD_TAINT".to_string(),
        tag: Some("sensitive_data".to_string()),
        forbidden_tags: None,
        error: None,
        pattern: None,
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    let result = PolicyEvaluator::evaluate(
        &policy,
        "read_file",
        &["SENSITIVE_READ".to_string()],
        &[],
        &HashSet::new(),
    )
    .unwrap();

    match result {
        Decision::AllowedWithSideEffects {
            taints_to_add,
            taints_to_remove,
        } => {
            assert_eq!(taints_to_add.len(), 1);
            assert!(taints_to_add.contains(&"sensitive_data".to_string()));
            assert!(taints_to_remove.is_empty());
        }
        _ => panic!("Expected AllowedWithSideEffects decision"),
    }
}

#[test]
fn test_add_taint_by_tool_class() {
    let mut static_rules = HashMap::new();
    static_rules.insert("read_file".to_string(), "ALLOW".to_string());

    let taint_rule = PolicyRule {
        tool: None,
        tool_class: Some("SENSITIVE_READ".to_string()),
        action: "ADD_TAINT".to_string(),
        tag: Some("sensitive_data".to_string()),
        forbidden_tags: None,
        error: None,
        pattern: None,
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    let result = PolicyEvaluator::evaluate(
        &policy,
        "read_file",
        &["SENSITIVE_READ".to_string()],
        &[],
        &HashSet::new(),
    )
    .unwrap();

    match result {
        Decision::AllowedWithSideEffects { taints_to_add, .. } => {
            assert!(taints_to_add.contains(&"sensitive_data".to_string()));
        }
        _ => panic!("Expected AllowedWithSideEffects decision"),
    }
}

#[test]
fn test_check_taint_blocks_when_tainted() {
    let mut static_rules = HashMap::new();
    static_rules.insert("web_search".to_string(), "ALLOW".to_string());

    let taint_rule = PolicyRule {
        tool: None,
        tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
        action: "CHECK_TAINT".to_string(),
        tag: None,
        forbidden_tags: Some(vec!["sensitive_data".to_string()]),
        error: Some("Exfiltration blocked".to_string()),
        pattern: None,
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    let mut current_taints = HashSet::new();
    current_taints.insert("sensitive_data".to_string());

    let result = PolicyEvaluator::evaluate(
        &policy,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &[],
        &current_taints,
    )
    .unwrap();

    match result {
        Decision::Denied { reason } => {
            assert_eq!(reason, "Exfiltration blocked");
        }
        _ => panic!("Expected Denied decision"),
    }
}

#[test]
fn test_check_taint_allows_when_not_tainted() {
    let mut static_rules = HashMap::new();
    static_rules.insert("web_search".to_string(), "ALLOW".to_string());

    let taint_rule = PolicyRule {
        tool: None,
        tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
        action: "CHECK_TAINT".to_string(),
        tag: None,
        forbidden_tags: Some(vec!["sensitive_data".to_string()]),
        error: Some("Exfiltration blocked".to_string()),
        pattern: None,
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    let current_taints = HashSet::new(); // No taints

    let result = PolicyEvaluator::evaluate(
        &policy,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &[],
        &current_taints,
    )
    .unwrap();

    assert!(matches!(result, Decision::Allowed));
}

#[test]
fn test_remove_taint_tracked() {
    // Note: Redis is append-only. REMOVE_TAINT is tracked for future implementation
    // (e.g., separate sanitization log, or computed state from history)
    let mut static_rules = HashMap::new();
    static_rules.insert("anonymize_text".to_string(), "ALLOW".to_string());

    let taint_rule = PolicyRule {
        tool: None,
        tool_class: Some("SANITIZER".to_string()),
        action: "REMOVE_TAINT".to_string(),
        tag: Some("sensitive_data".to_string()),
        forbidden_tags: None,
        error: None,
        pattern: None,
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    let mut current_taints = HashSet::new();
    current_taints.insert("sensitive_data".to_string());

    let result = PolicyEvaluator::evaluate(
        &policy,
        "anonymize_text",
        &["SANITIZER".to_string()],
        &[],
        &current_taints,
    )
    .unwrap();

    match result {
        Decision::AllowedWithSideEffects {
            taints_to_remove, ..
        } => {
            // REMOVE_TAINT action is tracked in decision
            // Actual implementation TBD (append-only constraint)
            assert!(taints_to_remove.contains(&"sensitive_data".to_string()));
        }
        _ => panic!("Expected AllowedWithSideEffects decision"),
    }
}

#[test]
fn test_multiple_taint_rules() {
    let mut static_rules = HashMap::new();
    static_rules.insert("read_file".to_string(), "ALLOW".to_string());

    let rule1 = PolicyRule {
        tool: Some("read_file".to_string()),
        tool_class: None,
        action: "ADD_TAINT".to_string(),
        tag: Some("taint_a".to_string()),
        forbidden_tags: None,
        error: None,
        pattern: None,
    };

    let rule2 = PolicyRule {
        tool: None,
        tool_class: Some("SENSITIVE_READ".to_string()),
        action: "ADD_TAINT".to_string(),
        tag: Some("taint_b".to_string()),
        forbidden_tags: None,
        error: None,
        pattern: None,
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![rule1, rule2],
    };

    let result = PolicyEvaluator::evaluate(
        &policy,
        "read_file",
        &["SENSITIVE_READ".to_string()],
        &[],
        &HashSet::new(),
    )
    .unwrap();

    match result {
        Decision::AllowedWithSideEffects { taints_to_add, .. } => {
            assert_eq!(taints_to_add.len(), 2);
            assert!(taints_to_add.contains(&"taint_a".to_string()));
            assert!(taints_to_add.contains(&"taint_b".to_string()));
        }
        _ => panic!("Expected AllowedWithSideEffects decision"),
    }
}

