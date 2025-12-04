// Tests for tool_args_match in logic patterns

use sentinel_interceptor::core::models::{PolicyDefinition, PolicyRule};
use sentinel_interceptor::utils::policy_validator::PolicyValidator;
use serde_json::json;
use std::collections::HashMap;

#[test]
fn test_tool_args_match_in_logic_pattern_rejected_for_class() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: None,
            tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
            action: "BLOCK_CURRENT".to_string(),
            tag: None,
            forbidden_tags: None,
            error: None,
            pattern: Some(json!({
                "type": "logic",
                "condition": {
                    "tool_args_match": {"destination": "unsafe_*"}
                }
            })),
            exceptions: None,
        }],
    };

    let result = PolicyValidator::validate_policies(&[policy]);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("tool_args_match"));
    assert!(err_msg.contains("logic patterns"));
    assert!(err_msg.contains("tool-specific rules"));
}

#[test]
fn test_tool_args_match_in_logic_pattern_allowed_for_tool() {
    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![PolicyRule {
            tool: Some("send_email".to_string()),
            tool_class: None,
            action: "BLOCK_CURRENT".to_string(),
            tag: None,
            forbidden_tags: None,
            error: None,
            pattern: Some(json!({
                "type": "logic",
                "condition": {
                    "AND": [
                        {"session_has_taint": "sensitive"},
                        {"tool_args_match": {"to": "*@external.com"}}
                    ]
                }
            })),
            exceptions: None,
        }],
    };

    assert!(PolicyValidator::validate_policies(&[policy]).is_ok());
}



