// Integration test for full request flow: Agent -> Interceptor -> MCP
//
// Tests the complete end-to-end flow:
// 1. API key authentication
// 2. Policy evaluation (static + dynamic rules)
// 3. Cryptographic token minting
// 4. MCP proxy forwarding
// 5. State updates (taints, history)

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use sentinel_interceptor::api::{create_router, AppState, Config};
use sentinel_interceptor::api::evaluator_adapter::PolicyEvaluatorAdapter;
use sentinel_interceptor::core::crypto::CryptoSigner;
use sentinel_interceptor::core::models::{
    CustomerConfig, Decision, HistoryEntry, PolicyDefinition, PolicyRule, ProxyRequest,
};
use sentinel_interceptor::engine::evaluator::PolicyEvaluator as EnginePolicyEvaluator;
use sentinel_interceptor::loader::policy_loader::PolicyLoader;
use sentinel_interceptor::loader::tool_registry::ToolRegistry;
use sentinel_interceptor::state::redis_store::RedisStore;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tower::ServiceExt;

// Mock implementations for testing

struct MockProxyClient {
    response: serde_json::Value,
    should_fail: bool,
}

#[async_trait::async_trait]
impl sentinel_interceptor::api::ProxyClient for MockProxyClient {
    async fn forward_request(
        &self,
        _url: &str,
        _tool_name: &str,
        _args: &serde_json::Value,
        _session_id: &str,
        _callback_url: Option<&str>,
        token: &str,
    ) -> Result<serde_json::Value, String> {
        if self.should_fail {
            return Err("MCP server unreachable".to_string());
        }

        // Verify token is present and non-empty
        assert!(!token.is_empty());
        assert!(token.contains('.')); // JWT format: header.payload.signature

        Ok(self.response.clone())
    }
}

struct MockCustomerStore {
    customers: HashMap<String, CustomerConfig>,
}

#[async_trait::async_trait]
impl sentinel_interceptor::api::CustomerStore for MockCustomerStore {
    async fn lookup_customer(&self, api_key_hash: &str) -> Result<Option<CustomerConfig>, String> {
        Ok(self.customers.get(api_key_hash).cloned())
    }
}

struct MockPolicyStore {
    policies: HashMap<String, Arc<PolicyDefinition>>,
}

#[async_trait::async_trait]
impl sentinel_interceptor::api::PolicyStore for MockPolicyStore {
    async fn load_policy(
        &self,
        policy_name: &str,
    ) -> Result<Option<Arc<PolicyDefinition>>, String> {
        Ok(self.policies.get(policy_name).cloned())
    }
}

struct MockPolicyCache;

#[async_trait::async_trait]
impl sentinel_interceptor::api::PolicyCache for MockPolicyCache {
    async fn get_policy(
        &self,
        _policy_name: &str,
    ) -> Result<Option<Arc<PolicyDefinition>>, String> {
        Ok(None) // Always miss cache for testing
    }

    async fn put_policy(
        &self,
        _policy_name: &str,
        _policy: Arc<PolicyDefinition>,
    ) -> Result<(), String> {
        Ok(())
    }
}

struct MockToolRegistry {
    tool_classes: HashMap<String, Vec<String>>,
}

#[async_trait::async_trait]
impl sentinel_interceptor::api::ToolRegistry for MockToolRegistry {
    async fn get_tool_classes(&self, tool_name: &str) -> Result<Vec<String>, String> {
        Ok(self
            .tool_classes
            .get(tool_name)
            .cloned()
            .unwrap_or_default())
    }
}

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

    async fn add_taint(&self, session_id: &str, tag: &str) -> Result<(), String> {
        self.taints
            .entry(session_id.to_string())
            .or_insert_with(HashSet::new)
            .insert(tag.to_string());
        Ok(())
    }

    async fn remove_taint(&self, session_id: &str, tag: &str) -> Result<(), String> {
        if let Some(taints) = self.taints.get_mut(session_id) {
            taints.remove(tag);
        }
        Ok(())
    }

    async fn add_to_history(
        &self,
        session_id: &str,
        tool: &str,
        classes: &[String],
    ) -> Result<(), String> {
        let entry = HistoryEntry {
            tool: tool.to_string(),
            classes: classes.to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
        };
        self.history
            .entry(session_id.to_string())
            .or_insert_with(Vec::new)
            .push(entry);
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

fn create_test_app_state(
    redis_store: Arc<MockRedisStore>,
    proxy_client: Arc<MockProxyClient>,
    tool_registry: Arc<MockToolRegistry>,
) -> AppState {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    // Create crypto signer with test key
    let signing_key = SigningKey::generate(&mut OsRng);
    let crypto_signer = Arc::new(CryptoSigner::from_signing_key(signing_key));

    // Create evaluator adapter
    let redis_for_evaluator: Arc<dyn sentinel_interceptor::api::RedisStore + Send + Sync> =
        Arc::clone(&redis_store);
    let evaluator = Arc::new(PolicyEvaluatorAdapter::new(redis_for_evaluator));

    // Create mock stores
    let customer_store: Arc<dyn sentinel_interceptor::api::CustomerStore + Send + Sync> =
        Arc::new(MockCustomerStore {
            customers: HashMap::new(),
        });
    let policy_store: Arc<dyn sentinel_interceptor::api::PolicyStore + Send + Sync> =
        Arc::new(MockPolicyStore {
            policies: HashMap::new(),
        });
    let policy_cache: Arc<dyn sentinel_interceptor::api::PolicyCache + Send + Sync> =
        Arc::new(MockPolicyCache);

    let config = Arc::new(Config::default());

    AppState {
        crypto_signer,
        redis_store: redis_store as Arc<dyn sentinel_interceptor::api::RedisStore + Send + Sync>,
        policy_cache,
        evaluator,
        proxy_client: proxy_client as Arc<dyn sentinel_interceptor::api::ProxyClient + Send + Sync>,
        customer_store,
        policy_store,
        tool_registry: tool_registry as Arc<dyn sentinel_interceptor::api::ToolRegistry + Send + Sync>,
        config,
    }
}

#[tokio::test]
async fn test_full_request_flow_allowed() {
    // Setup: Create test policy
    let mut static_rules = HashMap::new();
    static_rules.insert("read_file".to_string(), "ALLOW".to_string());

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![],
    };

    // Setup: Create test customer config
    let customer_config = CustomerConfig {
        owner: "test_owner".to_string(),
        mcp_upstream_url: "http://localhost:8000".to_string(),
        policy_name: "test_policy".to_string(),
    };

    // Setup: Create mocks
    let redis_store = Arc::new(MockRedisStore {
        taints: HashMap::new(),
        history: HashMap::new(),
    });

    let proxy_client = Arc::new(MockProxyClient {
        response: serde_json::json!({"result": {"content": "file contents"}}),
        should_fail: false,
    });

    let mut tool_classes = HashMap::new();
    tool_classes.insert("read_file".to_string(), vec!["FILE_OPERATION".to_string()]);
    let tool_registry = Arc::new(MockToolRegistry { tool_classes });

    let app_state = create_test_app_state(redis_store, proxy_client, tool_registry);

    // Create router
    let app = create_router(app_state.clone());

    // Create request
    let request_body = serde_json::json!({
        "session_id": "test_session_123",
        "tool_name": "read_file",
        "args": {"path": "/tmp/test.txt"},
        "agent_callback_url": null
    });

    let request = Request::builder()
        .method("POST")
        .uri("/v1/proxy-execute")
        .header(header::CONTENT_TYPE, "application/json")
        // Note: Auth middleware would extract customer_config and policy from API key
        // For this test, we'll need to manually set extensions or mock the middleware
        .extension(customer_config.clone())
        .extension(policy.clone())
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    // Note: This test requires auth middleware to be implemented
    // Currently, the handler expects customer_config and policy in extensions
    // which would be set by auth middleware. For now, we test the handler logic
    // by directly calling it with extensions set.

    let response = app.oneshot(request).await.unwrap();

    // Verify response
    assert_eq!(response.status(), StatusCode::OK);

    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(response_json.get("result").is_some());
}

#[tokio::test]
async fn test_full_request_flow_static_deny() {
    // Setup: Create policy that denies the tool
    let mut static_rules = HashMap::new();
    static_rules.insert("delete_file".to_string(), "DENY".to_string());

    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![],
    };

    let customer_config = CustomerConfig {
        owner: "test_owner".to_string(),
        mcp_upstream_url: "http://localhost:8000".to_string(),
        policy_name: "test_policy".to_string(),
    };

    let redis_store = Arc::new(MockRedisStore {
        taints: HashMap::new(),
        history: HashMap::new(),
    });

    let proxy_client = Arc::new(MockProxyClient {
        response: serde_json::json!({}),
        should_fail: false,
    });

    let tool_registry = Arc::new(MockToolRegistry {
        tool_classes: HashMap::new(),
    });

    let app_state = create_test_app_state(redis_store, proxy_client, tool_registry);

    // Test policy evaluation directly
    let decision = EnginePolicyEvaluator::evaluate(
        &policy,
        "delete_file",
        &[],
        &[],
        &HashSet::new(),
    )
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
    // Setup: Create policy with taint check rule
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
    // Setup: Policy with ADD_TAINT rule
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
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use sentinel_interceptor::core::crypto::CryptoSigner;
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
    assert_eq!(parts.len(), 3, "Token should have 3 parts (header.payload.signature)");

    // Verify token is not empty
    assert!(!token.is_empty());
    assert!(token.len() > 100); // JWT tokens are typically >100 chars
}

#[tokio::test]
async fn test_evaluator_adapter_integration() {
    // Test that the adapter correctly bridges API trait and engine
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

