// Unit tests for domain models

use sentinel_interceptor::core::models::*;
use serde_json::json;
use std::str::FromStr;

#[test]
fn test_session_id_from_str_valid() {
    let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
    let session_id = SessionId::from_str(uuid_str).unwrap();
    assert_eq!(session_id.to_string(), uuid_str);
}

#[test]
fn test_session_id_from_str_invalid() {
    let invalid = "not-a-uuid";
    assert!(SessionId::from_str(invalid).is_err());
}

#[test]
fn test_session_id_generate_unique() {
    let id1 = SessionId::generate();
    let id2 = SessionId::generate();
    assert_ne!(id1, id2);
}

#[test]
fn test_session_id_serialization() {
    let id = SessionId::generate();
    let json = serde_json::to_string(&id).unwrap();
    let deserialized: SessionId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, deserialized);
}

#[test]
fn test_tool_call_creation() {
    let tool_call = ToolCall {
        tool_name: "read_file".to_string(),
        args: json!({"path": "/tmp/file.txt"}),
    };
    
    assert_eq!(tool_call.tool_name, "read_file");
    assert_eq!(tool_call.args["path"], "/tmp/file.txt");
}

#[test]
fn test_proxy_request_serialization_round_trip() {
    let request = ProxyRequest {
        session_id: "test-session-123".to_string(),
        tool_name: "read_file".to_string(),
        args: json!({"path": "/tmp/file.txt"}),
        agent_callback_url: Some("http://example.com/callback".to_string()),
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: ProxyRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(request.session_id, deserialized.session_id);
    assert_eq!(request.tool_name, deserialized.tool_name);
    assert_eq!(request.agent_callback_url, deserialized.agent_callback_url);
    assert_eq!(request.args, deserialized.args);
}

#[test]
fn test_proxy_request_without_callback() {
    let request = ProxyRequest {
        session_id: "test-session".to_string(),
        tool_name: "read_file".to_string(),
        args: json!({}),
        agent_callback_url: None,
    };

    let json = serde_json::to_string(&request).unwrap();
    // Should not include callback_url in JSON when None
    assert!(!json.contains("agent_callback_url"));
    
    let deserialized: ProxyRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.agent_callback_url, None);
}

#[test]
fn test_decision_allowed() {
    let decision = Decision::Allowed;
    let json = serde_json::to_string(&decision).unwrap();
    let deserialized: Decision = serde_json::from_str(&json).unwrap();
    
    match deserialized {
        Decision::Allowed => (),
        _ => panic!("Expected Allowed variant"),
    }
}

#[test]
fn test_decision_denied() {
    let decision = Decision::Denied {
        reason: "Policy violation".to_string(),
    };

    let json = serde_json::to_string(&decision).unwrap();
    let deserialized: Decision = serde_json::from_str(&json).unwrap();

    match deserialized {
        Decision::Denied { reason } => assert_eq!(reason, "Policy violation"),
        _ => panic!("Expected Denied variant"),
    }
}

#[test]
fn test_decision_allowed_with_side_effects() {
    let decision = Decision::AllowedWithSideEffects {
        taints_to_add: vec!["sensitive_data".to_string()],
        taints_to_remove: vec!["old_taint".to_string()],
    };

    let json = serde_json::to_string(&decision).unwrap();
    let deserialized: Decision = serde_json::from_str(&json).unwrap();

    match deserialized {
        Decision::AllowedWithSideEffects {
            taints_to_add,
            taints_to_remove,
        } => {
            assert_eq!(taints_to_add, vec!["sensitive_data".to_string()]);
            assert_eq!(taints_to_remove, vec!["old_taint".to_string()]);
        }
        _ => panic!("Expected AllowedWithSideEffects variant"),
    }
}

#[test]
fn test_policy_rule_matches_tool_by_name() {
    let rule = PolicyRule {
        tool: Some("read_file".to_string()),
        tool_class: None,
        action: "ADD_TAINT".to_string(),
        tag: Some("sensitive_data".to_string()),
        forbidden_tags: None,
        error: None,
        pattern: None,
        exceptions: None,
    };

    assert!(rule.matches_tool("read_file", &[]));
    assert!(!rule.matches_tool("write_file", &[]));
}

#[test]
fn test_policy_rule_matches_tool_by_class() {
    let rule = PolicyRule {
        tool: None,
        tool_class: Some("SENSITIVE_READ".to_string()),
        action: "CHECK_TAINT".to_string(),
        tag: None,
        forbidden_tags: Some(vec!["sensitive_data".to_string()]),
        error: None,
        pattern: None,
        exceptions: None,
    };

    assert!(rule.matches_tool("any_tool", &["SENSITIVE_READ".to_string()]));
    assert!(rule.matches_tool("any_tool", &["OTHER".to_string(), "SENSITIVE_READ".to_string()]));
    assert!(!rule.matches_tool("any_tool", &["OTHER".to_string()]));
}

#[test]
fn test_policy_rule_matches_tool_both_name_and_class() {
    // If both tool and tool_class are set, either can match
    let rule = PolicyRule {
        tool: Some("read_file".to_string()),
        tool_class: Some("SENSITIVE_READ".to_string()),
        action: "ADD_TAINT".to_string(),
        tag: None,
        forbidden_tags: None,
        error: None,
        pattern: None,
        exceptions: None,
    };

    // Matches by name
    assert!(rule.matches_tool("read_file", &[]));
    // Matches by class
    assert!(rule.matches_tool("other_tool", &["SENSITIVE_READ".to_string()]));
    // Doesn't match if neither matches
    assert!(!rule.matches_tool("other_tool", &["OTHER".to_string()]));
}

#[test]
fn test_policy_rule_no_match_when_empty() {
    let rule = PolicyRule {
        tool: None,
        tool_class: None,
        action: "ADD_TAINT".to_string(),
        tag: None,
        forbidden_tags: None,
        error: None,
        pattern: None,
        exceptions: None,
    };

    // Should not match anything when both are None
    assert!(!rule.matches_tool("any_tool", &["ANY_CLASS".to_string()]));
}

#[test]
fn test_policy_definition_serialization() {
    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules: std::collections::HashMap::from([
            ("read_file".to_string(), "ALLOW".to_string()),
            ("delete_file".to_string(), "DENY".to_string()),
        ]),
        taint_rules: vec![PolicyRule {
            tool: Some("read_file".to_string()),
            tool_class: None,
            action: "ADD_TAINT".to_string(),
            tag: Some("sensitive_data".to_string()),
            forbidden_tags: None,
            error: None,
            pattern: None,
            exceptions: None,
        }],
    };

    let json = serde_json::to_string(&policy).unwrap();
    let deserialized: PolicyDefinition = serde_json::from_str(&json).unwrap();

    assert_eq!(policy.name, deserialized.name);
    assert_eq!(policy.static_rules.len(), deserialized.static_rules.len());
    assert_eq!(policy.taint_rules.len(), deserialized.taint_rules.len());
}

#[test]
fn test_customer_config_serialization() {
    let config = CustomerConfig {
        owner: "Test User".to_string(),
        mcp_upstream_url: "http://localhost:9000".to_string(),
        policy_name: "default_policy".to_string(),
    };

    let json = serde_json::to_string(&config).unwrap();
    let deserialized: CustomerConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(config.owner, deserialized.owner);
    assert_eq!(config.mcp_upstream_url, deserialized.mcp_upstream_url);
    assert_eq!(config.policy_name, deserialized.policy_name);
}

#[test]
fn test_history_entry_serialization() {
    let entry = HistoryEntry {
        tool: "read_file".to_string(),
        classes: vec!["SENSITIVE_READ".to_string(), "FILE_OPERATION".to_string()],
        timestamp: 1234567890.0,
    };

    let json = serde_json::to_string(&entry).unwrap();
    let deserialized: HistoryEntry = serde_json::from_str(&json).unwrap();

    assert_eq!(entry.tool, deserialized.tool);
    assert_eq!(entry.classes, deserialized.classes);
    assert_eq!(entry.timestamp, deserialized.timestamp);
}

