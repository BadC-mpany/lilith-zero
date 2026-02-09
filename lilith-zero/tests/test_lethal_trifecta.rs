//! Integration tests for lethal trifecta protection feature

use lilith_zero::config::Config;
use lilith_zero::engine_core::crypto::CryptoSigner;
use lilith_zero::engine_core::events::{SecurityDecision, SecurityEvent};
use lilith_zero::engine_core::models::{PolicyDefinition, PolicyRule, ResourceRule};
use lilith_zero::engine_core::security_core::SecurityCore;
use lilith_zero::engine_core::taint::Tainted;
use lilith_zero::engine_core::types::TaintedString;
use std::collections::HashMap;
use std::sync::Arc;

/// Helper to create a basic policy
fn create_test_policy(protect_trifecta: bool) -> PolicyDefinition {
    let mut static_rules = HashMap::new();
    static_rules.insert("read_db".to_string(), "ALLOW".to_string());
    static_rules.insert("fetch_url".to_string(), "ALLOW".to_string());
    static_rules.insert("send_email".to_string(), "ALLOW".to_string());
    static_rules.insert("post_api".to_string(), "ALLOW".to_string());

    PolicyDefinition {
        id: "test-policy".to_string(),
        customer_id: "test-customer".to_string(),
        name: "Test Lethal Trifecta Policy".to_string(),
        version: 1,
        static_rules,
        taint_rules: vec![
            // Classify tools - each tool explicitly adds its taints
            PolicyRule {
                tool: Some("read_db".to_string()),
                tool_class: None,
                action: "ADD_TAINT".to_string(),
                tag: Some("ACCESS_PRIVATE".to_string()),
                forbidden_tags: None,
                required_taints: None,
                error: None,
                pattern: None,
                exceptions: None,
            },
            PolicyRule {
                tool: Some("fetch_url".to_string()),
                tool_class: None,
                action: "ADD_TAINT".to_string(),
                tag: Some("UNTRUSTED_SOURCE".to_string()),
                forbidden_tags: None,
                required_taints: None,
                error: None,
                pattern: None,
                exceptions: None,
            },
            PolicyRule {
                tool: Some("send_email".to_string()),
                tool_class: None,
                action: "ADD_TAINT".to_string(),
                tag: Some("EXFILTRATION".to_string()),
                forbidden_tags: None,
                required_taints: None,
                error: None,
                pattern: None,
                exceptions: None,
            },
            PolicyRule {
                tool: Some("post_api".to_string()),
                tool_class: None,
                action: "ADD_TAINT".to_string(),
                tag: Some("EXFILTRATION".to_string()),
                forbidden_tags: None,
                required_taints: None,
                error: None,
                pattern: None,
                exceptions: None,
            },
        ],
        created_at: None,
        resource_rules: vec![
            ResourceRule {
                uri_pattern: "file:///private/*".to_string(),
                action: "ALLOW".to_string(),
                exceptions: None,
                taints_to_add: Some(vec!["ACCESS_PRIVATE".to_string()]),
            },
            ResourceRule {
                uri_pattern: "http*".to_string(),
                action: "ALLOW".to_string(),
                exceptions: None,
                taints_to_add: Some(vec!["UNTRUSTED_SOURCE".to_string()]),
            },
        ],
        protect_lethal_trifecta: protect_trifecta,
    }
}

#[tokio::test]
async fn test_trifecta_protection_enabled() {
    let config = Arc::new(Config::default());
    let signer = CryptoSigner::try_new().unwrap();
    let mut core = SecurityCore::new(config, signer).unwrap();

    // Set policy with protection enabled
    let policy = create_test_policy(true);
    core.set_policy(policy);

    // Get valid session token
    let session_token = core.session_id.clone();

    // Step 1: Access private data
    let read_db_event = SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("1".to_string()),
        tool_name: TaintedString::new("read_db".to_string()),
        arguments: Tainted::new(serde_json::Value::Null, vec![]),
        session_token: Some(session_token.clone()),
    };

    let decision = core.evaluate(read_db_event).await;
    match decision {
        SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {}
        other => panic!("Expected Allow for read_db, got {:?}", other),
    }

    // Step 2: Access untrusted source
    let fetch_url_event = SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("2".to_string()),
        tool_name: TaintedString::new("fetch_url".to_string()),
        arguments: Tainted::new(serde_json::Value::Null, vec![]),
        session_token: Some(session_token.clone()),
    };

    let decision = core.evaluate(fetch_url_event).await;
    match decision {
        SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {}
        other => panic!("Expected Allow for fetch_url, got {:?}", other),
    }

    // Step 3: Try to exfiltrate - Should be BLOCKED
    let send_email_event = SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("3".to_string()),
        tool_name: TaintedString::new("send_email".to_string()),
        arguments: Tainted::new(serde_json::Value::Null, vec![]),
        session_token: Some(session_token.clone()),
    };

    let decision = core.evaluate(send_email_event).await;
    match decision {
        SecurityDecision::Deny { reason, .. } => {
            assert!(
                reason.contains("lethal trifecta"),
                "Expected trifecta error message, got: {}",
                reason
            );
        }
        other => panic!("Expected Deny for exfiltration, got {:?}", other),
    }
}

#[tokio::test]
async fn test_trifecta_protection_disabled() {
    let config = Arc::new(Config::default());
    let signer = CryptoSigner::try_new().unwrap();
    let mut core = SecurityCore::new(config, signer).unwrap();

    // Set policy with protection DISABLED
    let policy = create_test_policy(false);
    core.set_policy(policy);

    let session_token = core.session_id.clone();

    // Access private data
    let read_db_event = SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("1".to_string()),
        tool_name: TaintedString::new("read_db".to_string()),
        arguments: Tainted::new(serde_json::Value::Null, vec![]),
        session_token: Some(session_token.clone()),
    };
    core.evaluate(read_db_event).await;

    // Access untrusted source
    let fetch_url_event = SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("2".to_string()),
        tool_name: TaintedString::new("fetch_url".to_string()),
        arguments: Tainted::new(serde_json::Value::Null, vec![]),
        session_token: Some(session_token.clone()),
    };
    core.evaluate(fetch_url_event).await;

    // Try to exfiltrate - Should be ALLOWED (no protection)
    let send_email_event = SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("3".to_string()),
        tool_name: TaintedString::new("send_email".to_string()),
        arguments: Tainted::new(serde_json::Value::Null, vec![]),
        session_token: Some(session_token.clone()),
    };

    let decision = core.evaluate(send_email_event).await;
    match decision {
        SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {}
        other => panic!("Expected Allow (no protection), got {:?}", other),
    }
}

#[tokio::test]
async fn test_exfiltration_allowed_before_trifecta_complete() {
    let config = Arc::new(Config::default());
    let signer = CryptoSigner::try_new().unwrap();
    let mut core = SecurityCore::new(config, signer).unwrap();

    let policy = create_test_policy(true);
    core.set_policy(policy);

    let session_token = core.session_id.clone();

    // Step 1: Try exfiltration FIRST (before trifecta is complete)
    let send_email_event = SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("1".to_string()),
        tool_name: TaintedString::new("send_email".to_string()),
        arguments: Tainted::new(serde_json::Value::Null, vec![]),
        session_token: Some(session_token.clone()),
    };

    let decision = core.evaluate(send_email_event).await;
    match decision {
        SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {}
        other => panic!("Expected Allow (trifecta not complete), got {:?}", other),
    }
}

#[tokio::test]
async fn test_resource_taints_contribute_to_trifecta() {
    let config = Arc::new(Config::default());
    let signer = CryptoSigner::try_new().unwrap();
    let mut core = SecurityCore::new(config, signer).unwrap();

    let policy = create_test_policy(true);
    core.set_policy(policy);

    let session_token = core.session_id.clone();

    // Step 1: Read private file (adds ACCESS_PRIVATE taint)
    let resource_event = SecurityEvent::ResourceRequest {
        request_id: serde_json::Value::String("1".to_string()),
        uri: TaintedString::new("file:///private/secret.txt".to_string()),
        session_token: Some(session_token.clone()),
    };

    let decision = core.evaluate(resource_event).await;
    match decision {
        SecurityDecision::AllowWithTransforms { taints_to_add, .. } => {
            assert!(taints_to_add.contains(&"ACCESS_PRIVATE".to_string()));
        }
        other => panic!("Expected AllowWithTransforms, got {:?}", other),
    }

    // Step 2: Read HTTP resource (adds UNTRUSTED_SOURCE taint)
    let http_event = SecurityEvent::ResourceRequest {
        request_id: serde_json::Value::String("2".to_string()),
        uri: TaintedString::new("https://malicious.com/payload".to_string()),
        session_token: Some(session_token.clone()),
    };

    let decision = core.evaluate(http_event).await;
    match decision {
        SecurityDecision::AllowWithTransforms { taints_to_add, .. } => {
            assert!(taints_to_add.contains(&"UNTRUSTED_SOURCE".to_string()));
        }
        other => panic!("Expected AllowWithTransforms, got {:?}", other),
    }

    // Step 3: Try exfiltration - Should be BLOCKED (trifecta complete via resources)
    let exfil_event = SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("3".to_string()),
        tool_name: TaintedString::new("post_api".to_string()),
        arguments: Tainted::new(serde_json::Value::Null, vec![]),
        session_token: Some(session_token.clone()),
    };

    let decision = core.evaluate(exfil_event).await;
    match decision {
        SecurityDecision::Deny { reason, .. } => {
            assert!(reason.contains("lethal trifecta"));
        }
        other => panic!("Expected Deny, got {:?}", other),
    }
}

#[tokio::test]
async fn test_only_one_taint_not_blocked() {
    let config = Arc::new(Config::default());
    let signer = CryptoSigner::try_new().unwrap();
    let mut core = SecurityCore::new(config, signer).unwrap();

    let policy = create_test_policy(true);
    core.set_policy(policy);

    let session_token = core.session_id.clone();

    // Only access private data (missing UNTRUSTED_SOURCE)
    let read_db_event = SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("1".to_string()),
        tool_name: TaintedString::new("read_db".to_string()),
        arguments: Tainted::new(serde_json::Value::Null, vec![]),
        session_token: Some(session_token.clone()),
    };
    core.evaluate(read_db_event).await;

    // Try exfiltration - Should be ALLOWED (trifecta incomplete)
    let send_email_event = SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("2".to_string()),
        tool_name: TaintedString::new("send_email".to_string()),
        arguments: Tainted::new(serde_json::Value::Null, vec![]),
        session_token: Some(session_token.clone()),
    };

    let decision = core.evaluate(send_email_event).await;
    match decision {
        SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {}
        other => panic!("Expected Allow (only one taint), got {:?}", other),
    }
}
