// Unit tests for policy validator

use sentinel_interceptor::core::models::{PolicyDefinition, PolicyRule, RuleException};
use sentinel_interceptor::utils::policy_validator::PolicyValidator;
use serde_json::json;
use std::collections::HashMap;

#[test]
fn test_valid_simple_policy() {
    let mut static_rules = HashMap::new();
    static_rules.insert("read_file".to_string(), "ALLOW".to_string());

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![PolicyRule {
            tool: Some("read_file".to_string()),
            tool_class: None,
            action: "ADD_TAINT".to_string(),
            tag: Some("sensitive".to_string()),
            forbidden_tags: None,
            error: None,
            pattern: None,
            exceptions: None,
        }],
    };

    assert!(PolicyValidator::validate_policies(&[policy]).is_ok());
}

#[test]
fn test_empty_policy_name_rejected() {
    let policy = PolicyDefinition {
        name: "".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![],
    };

    let result = PolicyValidator::validate_policies(&[policy]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("name cannot be empty"));
}

#[test]
fn test_invalid_static_rule_permission() {
    let mut static_rules = HashMap::new();
    static_rules.insert("tool".to_string(), "MAYBE".to_string());

    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules,
        taint_rules: vec![],
    };

    let result = PolicyValidator::validate_policies(&[policy]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("must be ALLOW or DENY"));
}

#[test]
fn test_rule_must_have_tool_or_class() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: None,
            tool_class: None, // Missing both!
            action: "ADD_TAINT".to_string(),
            tag: Some("test".to_string()),
            forbidden_tags: None,
            error: None,
            pattern: None,
            exceptions: None,
        }],
    };

    let result = PolicyValidator::validate_policies(&[policy]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("must specify either"));
}

#[test]
fn test_rule_cannot_have_both_tool_and_class() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: Some("tool1".to_string()),
            tool_class: Some("CLASS1".to_string()), // Both set!
            action: "ADD_TAINT".to_string(),
            tag: Some("test".to_string()),
            forbidden_tags: None,
            error: None,
            pattern: None,
            exceptions: None,
        }],
    };

    let result = PolicyValidator::validate_policies(&[policy]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot specify both"));
}

#[test]
fn test_unknown_action_rejected() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: Some("tool1".to_string()),
            tool_class: None,
            action: "INVALID_ACTION".to_string(),
            tag: None,
            forbidden_tags: None,
            error: None,
            pattern: None,
            exceptions: None,
        }],
    };

    let result = PolicyValidator::validate_policies(&[policy]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unknown action"));
}

#[test]
fn test_check_taint_requires_forbidden_tags() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: Some("tool1".to_string()),
            tool_class: None,
            action: "CHECK_TAINT".to_string(),
            tag: None,
            forbidden_tags: None, // Missing!
            error: None,
            pattern: None,
            exceptions: None,
        }],
    };

    let result = PolicyValidator::validate_policies(&[policy]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("requires 'forbidden_tags'"));
}

#[test]
fn test_add_taint_requires_tag() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: Some("tool1".to_string()),
            tool_class: None,
            action: "ADD_TAINT".to_string(),
            tag: None, // Missing!
            forbidden_tags: None,
            error: None,
            pattern: None,
            exceptions: None,
        }],
    };

    let result = PolicyValidator::validate_policies(&[policy]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("requires 'tag'"));
}

#[test]
fn test_sequence_pattern_requires_steps() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: Some("tool1".to_string()),
            tool_class: None,
            action: "BLOCK_SECOND".to_string(),
            tag: None,
            forbidden_tags: None,
            error: None,
            pattern: Some(json!({
                "type": "sequence"
                // Missing steps!
            })),
            exceptions: None,
        }],
    };

    let result = PolicyValidator::validate_policies(&[policy]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("missing 'steps'"));
}

#[test]
fn test_logic_pattern_requires_condition() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: Some("tool1".to_string()),
            tool_class: None,
            action: "BLOCK_CURRENT".to_string(),
            tag: None,
            forbidden_tags: None,
            error: None,
            pattern: Some(json!({
                "type": "logic"
                // Missing condition!
            })),
            exceptions: None,
        }],
    };

    let result = PolicyValidator::validate_policies(&[policy]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("missing 'condition'"));
}

#[test]
fn test_tool_args_match_rejected_in_class_rules() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: None,
            tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
            action: "CHECK_TAINT".to_string(),
            tag: None,
            forbidden_tags: Some(vec!["sensitive".to_string()]),
            error: None,
            pattern: None,
            exceptions: Some(vec![RuleException {
                condition: json!({
                    "tool_args_match": {"destination": "internal_*"}
                }),
                reason: Some("test".to_string()),
            }]),
        }],
    };

    let result = PolicyValidator::validate_policies(&[policy]);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("tool_args_match"));
    assert!(err_msg.contains("tool-specific rules"));
}

#[test]
fn test_tool_args_match_allowed_in_tool_rules() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: Some("send_email".to_string()),
            tool_class: None,
            action: "CHECK_TAINT".to_string(),
            tag: None,
            forbidden_tags: Some(vec!["sensitive".to_string()]),
            error: None,
            pattern: None,
            exceptions: Some(vec![RuleException {
                condition: json!({
                    "tool_args_match": {"to": "*@company.com"}
                }),
                reason: Some("Internal emails allowed".to_string()),
            }]),
        }],
    };

    assert!(PolicyValidator::validate_policies(&[policy]).is_ok());
}

#[test]
fn test_nested_tool_args_match_in_and_rejected_for_class() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: None,
            tool_class: Some("WRITE".to_string()),
            action: "CHECK_TAINT".to_string(),
            tag: None,
            forbidden_tags: Some(vec!["sensitive".to_string()]),
            error: None,
            pattern: None,
            exceptions: Some(vec![RuleException {
                condition: json!({
                    "AND": [
                        {"session_has_tool": "sanitize"},
                        {"tool_args_match": {"dest": "safe_*"}}
                    ]
                }),
                reason: Some("test".to_string()),
            }]),
        }],
    };

    let result = PolicyValidator::validate_policies(&[policy]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("tool_args_match"));
}

#[test]
fn test_valid_complex_exception() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: Some("send_email".to_string()),
            tool_class: None,
            action: "CHECK_TAINT".to_string(),
            tag: None,
            forbidden_tags: Some(vec!["sensitive".to_string()]),
            error: None,
            pattern: None,
            exceptions: Some(vec![RuleException {
                condition: json!({
                    "AND": [
                        {"session_has_tool": "anonymize"},
                        {"OR": [
                            {"tool_args_match": {"to": "*@company.com"}},
                            {"tool_args_match": {"to": "*@partner.com"}}
                        ]}
                    ]
                }),
                reason: Some("Allowed after anonymization to trusted domains".to_string()),
            }]),
        }],
    };

    assert!(PolicyValidator::validate_policies(&[policy]).is_ok());
}

