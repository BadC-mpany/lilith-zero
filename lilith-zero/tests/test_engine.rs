use lilith_zero::config::{Config, SecurityLevel};
use lilith_zero::engine_core::crypto::CryptoSigner;
use lilith_zero::engine_core::events::{SecurityDecision, SecurityEvent};
use lilith_zero::engine_core::security_core::SecurityCore;
use lilith_zero::engine_core::taint::Tainted;
use lilith_zero::engine_core::types::TaintedString;
use std::sync::Arc;

#[tokio::test]
async fn block_params_no_policy_denies() {
    let config = Arc::new(Config {
        security_level: SecurityLevel::BlockParams,
        ..Config::default()
    });
    let signer = CryptoSigner::try_new().unwrap();
    let mut core = SecurityCore::new(config, signer, None).unwrap();
    core.validate_session_tokens = false;

    let event = SecurityEvent::ToolRequest {
        tool_name: TaintedString::new("test_tool".to_string()),
        arguments: Tainted::new(serde_json::json!({}), vec![]),
        session_token: None,
        request_id: serde_json::Value::String("test_req".to_string()),
    };

    let decision = core.evaluate(event).await;
    assert!(
        matches!(decision, SecurityDecision::Deny { .. }),
        "expected Deny with no policy in BlockParams mode, got {decision:?}"
    );
}

#[tokio::test]
async fn audit_only_no_policy_allows() {
    let config = Arc::new(Config {
        security_level: SecurityLevel::AuditOnly,
        ..Config::default()
    });
    let signer = CryptoSigner::try_new().unwrap();
    let mut core = SecurityCore::new(config, signer, None).unwrap();
    core.validate_session_tokens = false;

    let event = SecurityEvent::ToolRequest {
        tool_name: TaintedString::new("test_tool".to_string()),
        arguments: Tainted::new(serde_json::json!({}), vec![]),
        session_token: None,
        request_id: serde_json::Value::String("test_req".to_string()),
    };

    let decision = core.evaluate(event).await;
    assert!(
        matches!(
            decision,
            SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. }
        ),
        "expected Allow with no policy in AuditOnly mode, got {decision:?}"
    );
}
