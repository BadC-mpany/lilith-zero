use lilith_zero::config::{Config, SecurityLevel};
use lilith_zero::engine_core::crypto::CryptoSigner;
use lilith_zero::engine_core::events::SecurityEvent;
use lilith_zero::engine_core::security_core::SecurityCore;
use lilith_zero::engine_core::taint::Tainted;
use lilith_zero::engine_core::types::TaintedString;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("--- Lilith Security Engine Scientist Test ---");

    // Case 1: Default config (BlockParams), No Policy
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
    println!("Decision with NO policy (BlockParams): {:?}", decision);

    // Case 2: AuditOnly config, No Policy
    let config_audit = Arc::new(Config {
        security_level: SecurityLevel::AuditOnly,
        ..Config::default()
    });
    let signer_audit = CryptoSigner::try_new().unwrap();
    let mut core_audit = SecurityCore::new(config_audit, signer_audit, None).unwrap();
    core_audit.validate_session_tokens = false;

    let event_audit = SecurityEvent::ToolRequest {
        tool_name: TaintedString::new("test_tool".to_string()),
        arguments: Tainted::new(serde_json::json!({}), vec![]),
        session_token: None,
        request_id: serde_json::Value::String("test_req".to_string()),
    };

    let decision_audit = core_audit.evaluate(event_audit).await;
    println!("Decision with NO policy (AuditOnly): {:?}", decision_audit);

    Ok(())
}
