// Common test utilities and helpers for all test modules

use sentinel_interceptor::api::*;
use sentinel_interceptor::core::models::*;
use sentinel_interceptor::core::crypto::CryptoSigner;
use sentinel_interceptor::core::errors::InterceptorError;
use sentinel_interceptor::config::Config;
use std::collections::HashMap;
use std::sync::Arc;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

/// Mock RedisStore implementation for testing
pub struct MockRedisStore {
    pub taints: HashMap<String, Vec<String>>,
    pub history: HashMap<String, Vec<HistoryEntry>>,
    pub ping_result: Result<(), String>,
    pub get_taints_should_fail: bool,
    pub get_history_should_fail: bool,
    pub get_history_should_timeout: bool,
    pub add_taint_should_fail: bool,
    pub add_to_history_should_fail: bool,
}

impl Default for MockRedisStore {
    fn default() -> Self {
        Self {
            taints: HashMap::new(),
            history: HashMap::new(),
            ping_result: Ok(()),
            get_taints_should_fail: false,
            get_history_should_fail: false,
            get_history_should_timeout: false,
            add_taint_should_fail: false,
            add_to_history_should_fail: false,
        }
    }
}

#[async_trait::async_trait]
impl RedisStore for MockRedisStore {
    async fn get_session_taints(&self, session_id: &str) -> Result<Vec<String>, InterceptorError> {
        if self.get_taints_should_fail {
             return Err(InterceptorError::StateError("Redis connection failed".to_string()));
        }
        Ok(self.taints.get(session_id).cloned().unwrap_or_default())
    }

    async fn add_taint(&self, _session_id: &str, _tag: &str) -> Result<(), InterceptorError> {
        if self.add_taint_should_fail {
            return Err(InterceptorError::StateError("Failed to add taint".to_string()));
        }
        Ok(())
    }

    async fn remove_taint(&self, _session_id: &str, _tag: &str) -> Result<(), InterceptorError> {
        Ok(())
    }

    async fn add_to_history(&self, _session_id: &str, _tool: &str, _classes: &[String]) -> Result<(), InterceptorError> {
        if self.add_to_history_should_fail {
            return Err(InterceptorError::StateError("Failed to add to history".to_string()));
        }
        Ok(())
    }

    async fn get_session_history(&self, session_id: &str) -> Result<Vec<HistoryEntry>, InterceptorError> {
        if self.get_history_should_timeout {
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            return Err(InterceptorError::StateError("Timeout".to_string()));
        }
        if self.get_history_should_fail {
            return Err(InterceptorError::StateError("Redis connection failed".to_string()));
        }
        Ok(self.history.get(session_id).cloned().unwrap_or_default())
    }

    async fn ping(&self) -> Result<(), InterceptorError> {
        self.ping_result.clone().map_err(InterceptorError::StateError)
    }
}

/// Mock PolicyStore implementation
pub struct MockPolicyStore {
    pub policies: HashMap<String, Arc<PolicyDefinition>>,
    pub should_fail: bool,
}

impl Default for MockPolicyStore {
    fn default() -> Self {
        Self {
            policies: HashMap::new(),
            should_fail: false,
        }
    }
}

#[async_trait::async_trait]
impl PolicyStore for MockPolicyStore {
    async fn load_policy(&self, policy_name: &str) -> Result<Option<Arc<PolicyDefinition>>, InterceptorError> {
        if self.should_fail {
            return Err(InterceptorError::StateError("Database error".to_string()));
        }
        Ok(self.policies.get(policy_name).cloned())
    }
}

/// Mock CustomerStore implementation
pub struct MockCustomerStore {
    pub customers: HashMap<String, CustomerConfig>,
    pub should_fail: bool,
}

impl Default for MockCustomerStore {
    fn default() -> Self {
        Self {
            customers: HashMap::new(),
            should_fail: false,
        }
    }
}

#[async_trait::async_trait]
impl CustomerStore for MockCustomerStore {
    async fn lookup_customer(&self, api_key_hash: &str) -> Result<Option<CustomerConfig>, InterceptorError> {
        if self.should_fail {
            return Err(InterceptorError::StateError("Database error".to_string()));
        }
        Ok(self.customers.get(api_key_hash).cloned())
    }
}

/// Mock ProxyClient implementation
pub struct MockProxyClient {
    pub response: Result<serde_json::Value, String>,
    pub should_delay: bool,
}

impl Default for MockProxyClient {
    fn default() -> Self {
        Self {
            response: Ok(serde_json::json!({"result": "success"})),
            should_delay: false,
        }
    }
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
    ) -> Result<serde_json::Value, InterceptorError> {
        if self.should_delay {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        self.response.clone().map_err(InterceptorError::McpProxyError)
    }
}

/// Mock PolicyEvaluator implementation
pub struct MockPolicyEvaluator {
    pub decision: Decision,
    pub should_fail: bool,
}

impl Default for MockPolicyEvaluator {
    fn default() -> Self {
        Self {
            decision: Decision::Allowed,
            should_fail: false,
        }
    }
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
    ) -> Result<Decision, InterceptorError> {
        if self.should_fail {
            Ok(Decision::Denied {
                reason: "Evaluation failed".to_string(),
            })
        } else {
            Ok(self.decision.clone())
        }
    }
}

/// Mock ToolRegistry implementation
pub struct MockToolRegistry {
    pub tool_classes: HashMap<String, Vec<String>>,
    pub should_fail: bool,
}

impl Default for MockToolRegistry {
    fn default() -> Self {
        Self {
            tool_classes: HashMap::new(),
            should_fail: false,
        }
    }
}

#[async_trait::async_trait]
impl ToolRegistry for MockToolRegistry {
    async fn get_tool_classes(&self, tool_name: &str) -> Result<Vec<String>, InterceptorError> {
        if self.should_fail {
            return Err(InterceptorError::StateError("Tool registry error".to_string()));
        }
        Ok(self.tool_classes.get(tool_name).cloned().unwrap_or_default())
    }
}

/// Create a test CryptoSigner with a generated key
pub fn create_test_crypto_signer() -> Arc<CryptoSigner> {
    let signing_key = SigningKey::generate(&mut OsRng);
    Arc::new(CryptoSigner::from_signing_key(signing_key))
}

/// Create a test AppState with configurable mocks
pub fn create_test_app_state(
    redis_store: Arc<dyn RedisStore + Send + Sync>,
    evaluator: Arc<dyn PolicyEvaluator + Send + Sync>,
    proxy_client: Arc<dyn ProxyClient + Send + Sync>,
    tool_registry: Arc<dyn ToolRegistry + Send + Sync>,
) -> AppState {
    let crypto_signer = create_test_crypto_signer();
    let policy_cache = Arc::new(MockPolicyCache);
    let customer_store = Arc::new(MockCustomerStore::default());
    let policy_store = Arc::new(MockPolicyStore::default());
    let config = Arc::new(Config::test_config());

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

/// Mock PolicyCache implementation
pub struct MockPolicyCache;

#[async_trait::async_trait]
impl PolicyCache for MockPolicyCache {
    async fn get_policy(&self, _policy_name: &str) -> Result<Option<Arc<PolicyDefinition>>, InterceptorError> {
        Ok(None)
    }

    async fn put_policy(&self, _policy_name: &str, _policy: Arc<PolicyDefinition>) -> Result<(), InterceptorError> {
        Ok(())
    }
}

/// Create a test policy with default rules
pub fn create_test_policy(name: &str) -> PolicyDefinition {
    let mut static_rules = HashMap::new();
    static_rules.insert("read_file".to_string(), "ALLOW".to_string());
    static_rules.insert("write_file".to_string(), "DENY".to_string());

    PolicyDefinition {
        name: name.to_string(),
        static_rules,
        taint_rules: vec![],
    }
}

/// Create a test ProxyRequest
pub fn create_test_request(tool_name: &str, session_id: &str) -> ProxyRequest {
    ProxyRequest {
        session_id: session_id.to_string(),
        tool_name: tool_name.to_string(),
        args: serde_json::json!({}),
        agent_callback_url: None,
    }
}

/// Create a test CustomerConfig
pub fn create_test_customer_config(owner: &str, policy_name: &str) -> CustomerConfig {
    CustomerConfig {
        owner: owner.to_string(),
        mcp_upstream_url: "http://localhost:9000".to_string(),
        policy_name: policy_name.to_string(),
    }
}

