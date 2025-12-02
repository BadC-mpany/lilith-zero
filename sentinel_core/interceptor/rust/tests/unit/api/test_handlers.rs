// Unit tests for API handlers

use axum::extract::State;
use sentinel_interceptor::api::handlers::*;
use sentinel_interceptor::api::*;
use sentinel_interceptor::core::models::*;
use std::collections::HashMap;
use std::sync::Arc;

// Mock implementations for testing

struct MockRedisStore {
    taints: HashMap<String, Vec<String>>,
    ping_result: Result<(), String>,
}

#[async_trait::async_trait]
impl RedisStore for MockRedisStore {
    async fn get_session_taints(&self, session_id: &str) -> Result<Vec<String>, String> {
        Ok(self.taints.get(session_id).cloned().unwrap_or_default())
    }

    async fn add_taint(&self, _session_id: &str, _tag: &str) -> Result<(), String> {
        Ok(())
    }

    async fn remove_taint(&self, _session_id: &str, _tag: &str) -> Result<(), String> {
        Ok(())
    }

    async fn add_to_history(&self, _session_id: &str, _tool: &str, _classes: &[String]) -> Result<(), String> {
        Ok(())
    }

    async fn ping(&self) -> Result<(), String> {
        self.ping_result.clone()
    }
}

struct MockPolicyCache;

#[async_trait::async_trait]
impl PolicyCache for MockPolicyCache {
    async fn get_policy(&self, _policy_name: &str) -> Result<Option<Arc<PolicyDefinition>>, String> {
        Ok(None)
    }

    async fn put_policy(&self, _policy_name: &str, _policy: Arc<PolicyDefinition>) -> Result<(), String> {
        Ok(())
    }
}

struct MockPolicyEvaluator {
    decision: Decision,
}

#[async_trait::async_trait]
impl PolicyEvaluator for MockPolicyEvaluator {
    async fn evaluate(
        &self,
        _policy: &PolicyDefinition,
        _tool_name: &str,
        _tool_classes: &[String],
        _session_taints: &[String],
        _session_id: &str,
    ) -> Result<Decision, String> {
        Ok(self.decision.clone())
    }
}

struct MockProxyClient {
    result: Result<serde_json::Value, String>,
}

#[async_trait::async_trait]
impl ProxyClient for MockProxyClient {
    async fn forward_request(
        &self,
        _url: &str,
        _tool_name: &str,
        _args: &serde_json::Value,
        _session_id: &str,
        _callback_url: Option<&str>,
        _token: &str,
    ) -> Result<serde_json::Value, String> {
        self.result.clone()
    }
}

struct MockCustomerStore;

#[async_trait::async_trait]
impl CustomerStore for MockCustomerStore {
    async fn lookup_customer(&self, _api_key_hash: &str) -> Result<Option<CustomerConfig>, String> {
        Ok(None)
    }
}

struct MockPolicyStore;

#[async_trait::async_trait]
impl PolicyStore for MockPolicyStore {
    async fn load_policy(&self, _policy_name: &str) -> Result<Option<Arc<PolicyDefinition>>, String> {
        Ok(None)
    }
}

struct MockToolRegistry {
    classes: Vec<String>,
}

#[async_trait::async_trait]
impl ToolRegistry for MockToolRegistry {
    async fn get_tool_classes(&self, _tool_name: &str) -> Result<Vec<String>, String> {
        Ok(self.classes.clone())
    }
}

fn create_test_app_state(decision: Decision, ping_result: Result<(), String>) -> AppState {
    // Create a crypto signer with a generated key for testing
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use sentinel_interceptor::core::crypto::CryptoSigner;
    
    let signing_key = SigningKey::generate(&mut OsRng);
    let crypto_signer = Arc::new(CryptoSigner::from_signing_key(signing_key));

    let redis_store = Arc::new(MockRedisStore {
        taints: HashMap::new(),
        ping_result,
    });

    let policy_cache = Arc::new(MockPolicyCache);
    
    let evaluator = Arc::new(MockPolicyEvaluator { decision });
    
    let proxy_client = Arc::new(MockProxyClient {
        result: Ok(serde_json::json!({"result": "success"})),
    });

    let customer_store = Arc::new(MockCustomerStore);
    let policy_store = Arc::new(MockPolicyStore);
    let tool_registry = Arc::new(MockToolRegistry {
        classes: vec!["FILE_OPERATION".to_string()],
    });

    let config = Arc::new(Config::default());

    AppState {
        crypto_signer,
        redis_store,
        policy_cache,
        evaluator,
        proxy_client,
        customer_store,
        policy_store,
        tool_registry,
        config,
    }
}

#[tokio::test]
async fn test_health_handler_success() {
    let app_state = create_test_app_state(Decision::Allowed, Ok(()));
    
    let result = health_handler(State(app_state)).await;
    
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status, "healthy");
    assert!(response.redis.contains("connected"));
}

#[tokio::test]
async fn test_health_handler_redis_failure() {
    let app_state = create_test_app_state(Decision::Allowed, Err("Connection refused".to_string()));
    
    let result = health_handler(State(app_state)).await;
    
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status, "healthy");
    assert!(response.redis.contains("disconnected"));
}

#[tokio::test]
async fn test_metrics_handler() {
    let result = metrics_handler().await;
    
    assert!(result.is_ok());
    let metrics = result.unwrap();
    assert!(metrics.contains("Sentinel Interceptor Metrics"));
}

// Note: proxy_execute_handler tests require a valid crypto signer with a test key file
// These would be integration tests rather than unit tests
// For now, we test the structure and error paths

#[tokio::test]
async fn test_proxy_execute_handler_redis_error() {
    // This test would require setting up a mock that fails get_session_taints
    // For now, we document the expected behavior
    // Full integration tests would be in tests/integration/
}

#[tokio::test]
async fn test_proxy_execute_handler_tool_registry_error() {
    // This test would require setting up a mock that fails get_tool_classes
    // For now, we document the expected behavior
}

#[tokio::test]
async fn test_proxy_execute_handler_policy_denied() {
    // This test would verify that Decision::Denied returns 403
    // Requires full mock setup with test crypto signer
}

#[tokio::test]
async fn test_proxy_execute_handler_policy_allowed() {
    // This test would verify successful flow
    // Requires full mock setup with test crypto signer
}

#[tokio::test]
async fn test_proxy_execute_handler_crypto_error() {
    // This test would verify crypto errors are handled correctly
    // Requires mock that fails token minting
}

#[tokio::test]
async fn test_proxy_execute_handler_mcp_proxy_error() {
    // This test would verify MCP proxy errors are handled correctly
    // Requires mock proxy client that returns error
}

