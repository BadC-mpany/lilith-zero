#![cfg(feature = "webhook")]

use cedar_policy::PolicySet;
use lilith_zero::engine_core::crypto::CryptoSigner;
use lilith_zero::engine_core::events::{SecurityDecision, SecurityEvent};
use lilith_zero::engine_core::security_core::SecurityCore;
use lilith_zero::engine_core::taint::Tainted;
use lilith_zero::engine_core::types::TaintedString;
use lilith_zero::server::copilot_studio::{to_hook_input, AnalyzeToolExecutionRequest};
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;

async fn setup_core(cedar_policy: PolicySet) -> SecurityCore {
    let config = Arc::new(lilith_zero::config::Config::default());
    let signer = CryptoSigner::try_new().unwrap();
    let mut core = SecurityCore::new(config, signer, None).unwrap();
    core.set_cedar_policy(cedar_policy);
    core.validate_session_tokens = false;

    // Perform handshake to initialize session
    let handshake = SecurityEvent::Handshake {
        protocol_version: "test".to_string(),
        client_info: json!({}),
        audience_token: None,
        capabilities: json!({}),
    };
    let _ = core.evaluate(handshake).await;

    core
}

#[tokio::test]
async fn test_reproduce_resource_block() {
    let raw_payload = r#"{
        "plannerContext": { "userMessage": "test" },
        "toolDefinition": {
            "id": "tool-1",
            "type": "ToolDefinition",
            "name": "Create-table",
            "description": "test"
        },
        "inputValues": {
            "drive": "doc_libG",
            "Range": "table_rangeG"
        },
        "conversationMetadata": {
            "agent": { "id": "5be3e14e", "tenantId": "t", "environmentId": "e", "isPublished": false },
            "conversationId": "8aef8b72-87d7-45d9-a79b-0d1463ecdc5c"
        }
    }"#;

    let request: AnalyzeToolExecutionRequest = serde_json::from_str(raw_payload).unwrap();
    let hook_input = to_hook_input(&request);

    // Mismatching policy
    let cedar_policy_src = r#"
        permit(
            principal,
            action in [Action::"tools/call", Action::"resources/read", Action::"resources/write"],
            resource
        ) when {
            resource == Resource::"CreateTable"
        };
    "#;
    let policy_set = PolicySet::from_str(cedar_policy_src).expect("valid policy");
    let mut core = setup_core(policy_set).await;

    // We must use the SAME session ID that was initialized or set it explicitly
    core.session_id = "8aef8b72-87d7-45d9-a79b-0d1463ecdc5c".to_string();

    let event = SecurityEvent::ToolRequest {
        request_id: json!("1"),
        tool_name: TaintedString::new(hook_input.tool_name.unwrap()),
        arguments: Tainted::new(hook_input.tool_input.unwrap(), vec![]),
        session_token: None, // Since validate_session_tokens is false
    };

    let decision = core.evaluate(event).await;

    if let SecurityDecision::Deny { reason, .. } = decision {
        println!("Successfully reproduced block: {}", reason);
        // Should be denied by resource rules because of name mismatch
        assert!(
            reason.contains("Path 'drive' blocked by resource rules")
                || reason.contains("denied by policy")
        );
    } else {
        panic!("Expected DENY but got ALLOW (Decision: {:?}).", decision);
    }
}

#[tokio::test]
async fn test_fix_verification() {
    let raw_payload = r#"{
        "plannerContext": { "userMessage": "test" },
        "toolDefinition": {
            "id": "tool-1",
            "type": "ToolDefinition",
            "name": "Create-table",
            "description": "test"
        },
        "inputValues": {
            "drive": "doc_libG",
            "Range": "table_rangeG"
        },
        "conversationMetadata": {
            "agent": { "id": "agent-1", "tenantId": "t", "environmentId": "e", "isPublished": false },
            "conversationId": "conv-1"
        }
    }"#;

    let request: AnalyzeToolExecutionRequest = serde_json::from_str(raw_payload).unwrap();
    let hook_input = to_hook_input(&request);

    // Fixed policy matching 'Create-table'
    let cedar_policy_src = r#"
        permit(
            principal,
            action in [Action::"tools/call", Action::"resources/read", Action::"resources/write"],
            resource
        ) when {
            resource == Resource::"Create-table"
        };
    "#;
    let policy_set = PolicySet::from_str(cedar_policy_src).expect("valid policy");
    let mut core = setup_core(policy_set).await;
    core.session_id = "conv-1".to_string();

    let event = SecurityEvent::ToolRequest {
        request_id: json!("1"),
        tool_name: TaintedString::new(hook_input.tool_name.unwrap()),
        arguments: Tainted::new(hook_input.tool_input.unwrap(), vec![]),
        session_token: None,
    };

    let decision = core.evaluate(event).await;

    assert!(
        matches!(
            decision,
            SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. }
        ),
        "Decision was: {:?}",
        decision
    );
}
