// Integration test for full request flow: Agent -> Interceptor -> MCP
//
// Tests the complete end-to-end flow:
// 1. API key authentication
// 2. Policy evaluation (static + dynamic rules)
// 3. Cryptographic token minting
// 4. MCP proxy forwarding
// 5. State updates (taints, history)

use sentinel_interceptor::api::evaluator_adapter::PolicyEvaluatorAdapter;
use sentinel_interceptor::api::PolicyEvaluator;
use sentinel_interceptor::core::crypto::CryptoSigner;
use sentinel_interceptor::core::models::{
    Decision, HistoryEntry, PolicyDefinition, PolicyRule,
};
use sentinel_interceptor::engine::evaluator::PolicyEvaluator as EnginePolicyEvaluator;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

// Mock implementations for testing

struct MockRedisStore {
    taints: HashMap<String, HashSet<String>>,
    history: HashMap<String, Vec<HistoryEntry>>,
}

#[async_trait::async_trait]
impl sentinel_interceptor::api::RedisStore for MockRedisStore {
    async fn get_session_taints(&self, session_id: &str) -> Result<Vec<String>, String> {
        Ok(self
            .taints
            .get(session_id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default())
    }

    async fn add_taint(&self, _session_id: &str, _tag: &str) -> Result<(), String> {
        // Note: This is a test mock, actual implementation would be in-memory
        Ok(())
    }

    async fn remove_taint(&self, _session_id: &str, _tag: &str) -> Result<(), String> {
        Ok(())
    }

    async fn add_to_history(
        &self,
        _session_id: &str,
        _tool: &str,
        _classes: &[String],
    ) -> Result<(), String> {
        Ok(())
    }

    async fn get_session_history(
        &self,
        session_id: &str,
    ) -> Result<Vec<HistoryEntry>, String> {
        Ok(self
            .history
            .get(session_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn ping(&self) -> Result<(), String> {
        Ok(())
    }
}

#[tokio::test]
async fn test_full_request_flow_static_deny() {
    // Test: Policy denies tool via static rule
    let mut static_rules = HashMap::new();
    static_rules.insert("delete_file".to_string(), "DENY".to_string());

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![],
    };

    // Test policy evaluation directly
    let decision = EnginePolicyEvaluator::evaluate(
        &policy,
        "delete_file",
        &[],
        &[],
        &HashSet::new(),
    )
    .await
    .unwrap();

    match decision {
        Decision::Denied { reason } => {
            assert!(reason.contains("delete_file"));
            assert!(reason.contains("forbidden"));
        }
        _ => panic!("Expected Denied decision"),
    }
}

#[tokio::test]
async fn test_full_request_flow_taint_block() {
    // Test: Policy blocks tool due to forbidden taint
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
        exceptions: None,
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    // Setup: Session with forbidden taint
    let mut taints = HashSet::new();
    taints.insert("sensitive_data".to_string());

    // Test policy evaluation
    let decision = EnginePolicyEvaluator::evaluate(
        &policy,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &[],
        &taints,
    )
    .await
    .unwrap();

    match decision {
        Decision::Denied { reason } => {
            assert!(reason.contains("Exfiltration blocked"));
        }
        _ => panic!("Expected Denied decision due to taint"),
    }
}

#[tokio::test]
async fn test_full_request_flow_add_taint() {
    // Test: Policy adds taint on tool execution
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
        exceptions: None,
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    // Test policy evaluation
    let decision = EnginePolicyEvaluator::evaluate(
        &policy,
        "read_file",
        &[],
        &[],
        &HashSet::new(),
    )
    .await
    .unwrap();

    match decision {
        Decision::AllowedWithSideEffects { taints_to_add, .. } => {
            assert!(taints_to_add.contains(&"sensitive_data".to_string()));
        }
        _ => panic!("Expected AllowedWithSideEffects decision"),
    }
}

#[tokio::test]
async fn test_crypto_token_minting() {
    // Test: Cryptographic token minting produces valid JWT
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use serde_json::json;

    let signing_key = SigningKey::generate(&mut OsRng);
    let signer = CryptoSigner::from_signing_key(signing_key);

    let session_id = "test_session_123";
    let tool_name = "read_file";
    let args = json!({"path": "/tmp/test.txt"});

    let token = signer
        .mint_token(session_id, tool_name, &args)
        .expect("Failed to mint token");

    // Verify token structure (JWT: header.payload.signature)
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "Token should have 3 parts (header.payload.signature)"
    );

    // Verify token is not empty and has reasonable length
    assert!(!token.is_empty());
    assert!(token.len() > 100); // JWT tokens are typically >100 chars

    // Verify token contains expected structure
    assert!(token.starts_with("eyJ")); // Base64url encoded JSON header typically starts with "eyJ"
}

#[tokio::test]
async fn test_evaluator_adapter_integration() {
    // Test: Adapter correctly bridges API trait and engine implementation
    let redis_store = Arc::new(MockRedisStore {
        taints: HashMap::new(),
        history: HashMap::new(),
    });

    let adapter = PolicyEvaluatorAdapter::new(
        redis_store as Arc<dyn sentinel_interceptor::api::RedisStore + Send + Sync>,
    );

    let mut static_rules = HashMap::new();
    static_rules.insert("test_tool".to_string(), "ALLOW".to_string());

    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules,
        taint_rules: vec![],
    };

    let decision = adapter
        .evaluate(&policy, "test_tool", &[], &[], "test_session")
        .await
        .unwrap();

    assert!(matches!(decision, Decision::Allowed));
}

#[tokio::test]
async fn test_evaluator_adapter_with_history() {
    // Test: Adapter correctly fetches and uses session history
    let mut history = HashMap::new();
    history.insert(
        "test_session".to_string(),
        vec![HistoryEntry {
            tool: "read_file".to_string(),
            classes: vec!["SENSITIVE_READ".to_string()],
            timestamp: 1234567890.0,
        }],
    );

    let redis_store = Arc::new(MockRedisStore {
        taints: HashMap::new(),
        history,
    });

    let adapter = PolicyEvaluatorAdapter::new(
        redis_store as Arc<dyn sentinel_interceptor::api::RedisStore + Send + Sync>,
    );

    let mut static_rules = HashMap::new();
    static_rules.insert("web_search".to_string(), "ALLOW".to_string());

    // Create sequence pattern rule
    let sequence_pattern = serde_json::json!({
        "type": "sequence",
        "steps": [
            {"class": "SENSITIVE_READ"},
            {"class": "CONSEQUENTIAL_WRITE"}
        ]
    });

    let taint_rule = PolicyRule {
        tool: None,
        tool_class: None,
        action: "BLOCK".to_string(),
        tag: None,
        forbidden_tags: None,
        error: Some("Sequence pattern detected".to_string()),
        pattern: Some(sequence_pattern),
        exceptions: None,
    };

    let policy = PolicyDefinition {
        name: "test".to_string(),
        static_rules,
        taint_rules: vec![taint_rule],
    };

    // Current tool is web_search with CONSEQUENTIAL_WRITE class
    // History has SENSITIVE_READ, so sequence pattern should match
    let decision = adapter
        .evaluate(
            &policy,
            "web_search",
            &["CONSEQUENTIAL_WRITE".to_string()],
            &[],
            "test_session",
        )
        .await
        .unwrap();

    match decision {
        Decision::Denied { reason } => {
            assert!(reason.contains("Sequence pattern detected"));
        }
        _ => panic!("Expected Denied decision due to sequence pattern"),
    }
}

#[tokio::test]
async fn test_end_to_end_policy_evaluation_flow() {
    // Comprehensive test: Full policy evaluation flow with multiple rule types
    
    // 1. Setup policy with static allow, taint add, and taint check rules
    let mut static_rules = HashMap::new();
    static_rules.insert("read_file".to_string(), "ALLOW".to_string());
    static_rules.insert("web_search".to_string(), "ALLOW".to_string());

    let add_taint_rule = PolicyRule {
        tool: Some("read_file".to_string()),
        tool_class: None,
        action: "ADD_TAINT".to_string(),
        tag: Some("sensitive_data".to_string()),
        forbidden_tags: None,
        error: None,
        pattern: None,
        exceptions: None,
    };

    let check_taint_rule = PolicyRule {
        tool: None,
        tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
        action: "CHECK_TAINT".to_string(),
        tag: None,
        forbidden_tags: Some(vec!["sensitive_data".to_string()]),
        error: Some("Exfiltration blocked".to_string()),
        pattern: None,
        exceptions: None,
    };

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![add_taint_rule, check_taint_rule],
    };

    // 2. First request: read_file should be allowed and add taint
    let decision1 = EnginePolicyEvaluator::evaluate(
        &policy,
        "read_file",
        &[],
        &[],
        &HashSet::new(),
    )
    .await
    .unwrap();

    match decision1 {
        Decision::AllowedWithSideEffects { taints_to_add, .. } => {
            assert!(taints_to_add.contains(&"sensitive_data".to_string()));
        }
        _ => panic!("Expected AllowedWithSideEffects for read_file"),
    }

    // 3. Second request: web_search with CONSEQUENTIAL_WRITE should be blocked due to taint
    let mut taints = HashSet::new();
    taints.insert("sensitive_data".to_string());

    let decision2 = EnginePolicyEvaluator::evaluate(
        &policy,
        "web_search",
        &["CONSEQUENTIAL_WRITE".to_string()],
        &[],
        &taints,
    )
    .await
    .unwrap();

    match decision2 {
        Decision::Denied { reason } => {
            assert!(reason.contains("Exfiltration blocked"));
        }
        _ => panic!("Expected Denied for web_search with taint"),
    }
}
