// Integration tests for auth middleware

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use sentinel_interceptor::api::{create_router, AppState, Config};
use sentinel_interceptor::auth::audit_logger::AuditLogger;
use sentinel_interceptor::auth::auth_middleware::AuthState;
use sentinel_interceptor::auth::customer_store::YamlCustomerStore;
use sentinel_interceptor::auth::policy_store::YamlPolicyStore;
use sentinel_interceptor::core::crypto::CryptoSigner;
use sentinel_interceptor::loader::policy_loader::PolicyLoader;
use sentinel_interceptor::loader::tool_registry::ToolRegistry;
use sentinel_interceptor::state::redis_store::RedisStore;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tower::ServiceExt;

// Mock implementations for testing
struct MockProxyClient;
struct MockPolicyCache;
struct MockPolicyEvaluator;
struct MockToolRegistry;
struct MockRedisStore;

#[async_trait::async_trait]
impl sentinel_interceptor::api::ProxyClient for MockProxyClient {
    async fn forward_request(
        &self,
        _url: &str,
        _tool_name: &str,
        _args: &serde_json::Value,
        _session_id: &str,
        _callback_url: Option<&str>,
        _token: &str,
    ) -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({"result": "success"}))
    }
}

#[async_trait::async_trait]
impl sentinel_interceptor::api::PolicyCache for MockPolicyCache {
    async fn get_policy(
        &self,
        _policy_name: &str,
    ) -> Result<Option<Arc<sentinel_interceptor::core::models::PolicyDefinition>>, String> {
        Ok(None)
    }

    async fn put_policy(
        &self,
        _policy_name: &str,
        _policy: Arc<sentinel_interceptor::core::models::PolicyDefinition>,
    ) -> Result<(), String> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl sentinel_interceptor::api::PolicyEvaluator for MockPolicyEvaluator {
    async fn evaluate(
        &self,
        _policy: &sentinel_interceptor::core::models::PolicyDefinition,
        _tool_name: &str,
        _tool_classes: &[String],
        _session_taints: &[String],
        _session_id: &str,
    ) -> Result<sentinel_interceptor::core::models::Decision, String> {
        Ok(sentinel_interceptor::core::models::Decision::Allowed)
    }
}

#[async_trait::async_trait]
impl sentinel_interceptor::api::ToolRegistry for MockToolRegistry {
    async fn get_tool_classes(&self, _tool_name: &str) -> Result<Vec<String>, String> {
        Ok(vec![])
    }
}

#[async_trait::async_trait]
impl sentinel_interceptor::api::RedisStore for MockRedisStore {
    async fn get_session_taints(&self, _session_id: &str) -> Result<Vec<String>, String> {
        Ok(vec![])
    }

    async fn add_taint(&self, _session_id: &str, _tag: &str) -> Result<(), String> {
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
        _session_id: &str,
    ) -> Result<Vec<sentinel_interceptor::core::models::HistoryEntry>, String> {
        Ok(vec![])
    }

    async fn ping(&self) -> Result<(), String> {
        Ok(())
    }
}

fn create_test_app_state() -> AppState {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let crypto_signer = Arc::new(CryptoSigner::from_signing_key(signing_key));

    AppState {
        crypto_signer,
        redis_store: Arc::new(MockRedisStore) as Arc<dyn sentinel_interceptor::api::RedisStore + Send + Sync>,
        policy_cache: Arc::new(MockPolicyCache) as Arc<dyn sentinel_interceptor::api::PolicyCache + Send + Sync>,
        evaluator: Arc::new(MockPolicyEvaluator) as Arc<dyn sentinel_interceptor::api::PolicyEvaluator + Send + Sync>,
        proxy_client: Arc::new(MockProxyClient) as Arc<dyn sentinel_interceptor::api::ProxyClient + Send + Sync>,
        customer_store: Arc::new(MockCustomerStore { customers: HashMap::new() }) as Arc<dyn sentinel_interceptor::api::CustomerStore + Send + Sync>,
        policy_store: Arc::new(MockPolicyStore { policies: HashMap::new() }) as Arc<dyn sentinel_interceptor::api::PolicyStore + Send + Sync>,
        tool_registry: Arc::new(MockToolRegistry) as Arc<dyn sentinel_interceptor::api::ToolRegistry + Send + Sync>,
        config: Arc::new(Config::default()),
    }
}

struct MockCustomerStore {
    customers: HashMap<String, sentinel_interceptor::core::models::CustomerConfig>,
}

#[async_trait::async_trait]
impl sentinel_interceptor::api::CustomerStore for MockCustomerStore {
    async fn lookup_customer(
        &self,
        _api_key_hash: &str,
    ) -> Result<Option<sentinel_interceptor::core::models::CustomerConfig>, String> {
        Ok(None)
    }
}

struct MockPolicyStore {
    policies: HashMap<String, Arc<sentinel_interceptor::core::models::PolicyDefinition>>,
}

#[async_trait::async_trait]
impl sentinel_interceptor::api::PolicyStore for MockPolicyStore {
    async fn load_policy(
        &self,
        _policy_name: &str,
    ) -> Result<Option<Arc<sentinel_interceptor::core::models::PolicyDefinition>>, String> {
        Ok(None)
    }
}

#[tokio::test]
async fn test_auth_middleware_missing_api_key() {
    let yaml_content = r#"
customers:
  - api_key: "test_key_123"
    owner: "test_owner"
    mcp_upstream_url: "http://localhost:9000"
    policy_name: "test_policy"
policies:
  - name: "test_policy"
    static_rules: {}
    taint_rules: []
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", yaml_content).unwrap();
    let path = temp_file.path();

    let loader = PolicyLoader::from_file(path).unwrap();
    let customer_store = Arc::new(YamlCustomerStore::new(loader.clone()));
    let policy_store = Arc::new(YamlPolicyStore::new(loader));
    let audit_logger = Arc::new(AuditLogger::new(None));

    let auth_state = Arc::new(AuthState {
        customer_store: customer_store as Arc<dyn sentinel_interceptor::api::CustomerStore + Send + Sync>,
        policy_store: policy_store as Arc<dyn sentinel_interceptor::api::PolicyStore + Send + Sync>,
        audit_logger,
        yaml_fallback: Some(loader),
    });

    let app_state = create_test_app_state();
    let app = create_router(app_state, Some(auth_state));

    // Request without API key
    let request = Request::builder()
        .method("POST")
        .uri("/v1/proxy-execute")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"session_id":"test","tool_name":"test","args":{}}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_middleware_invalid_api_key() {
    let yaml_content = r#"
customers:
  - api_key: "test_key_123"
    owner: "test_owner"
    mcp_upstream_url: "http://localhost:9000"
    policy_name: "test_policy"
policies:
  - name: "test_policy"
    static_rules: {}
    taint_rules: []
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", yaml_content).unwrap();
    let path = temp_file.path();

    let loader = PolicyLoader::from_file(path).unwrap();
    let customer_store = Arc::new(YamlCustomerStore::new(loader.clone()));
    let policy_store = Arc::new(YamlPolicyStore::new(loader));
    let audit_logger = Arc::new(AuditLogger::new(None));

    let auth_state = Arc::new(AuthState {
        customer_store: customer_store as Arc<dyn sentinel_interceptor::api::CustomerStore + Send + Sync>,
        policy_store: policy_store as Arc<dyn sentinel_interceptor::api::PolicyStore + Send + Sync>,
        audit_logger,
        yaml_fallback: Some(loader),
    });

    let app_state = create_test_app_state();
    let app = create_router(app_state, Some(auth_state));

    // Request with invalid API key
    let request = Request::builder()
        .method("POST")
        .uri("/v1/proxy-execute")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-API-Key", "invalid_key")
        .body(Body::from(r#"{"session_id":"test","tool_name":"test","args":{}}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_middleware_health_endpoint_bypass() {
    let yaml_content = r#"
customers:
  - api_key: "test_key_123"
    owner: "test_owner"
    mcp_upstream_url: "http://localhost:9000"
    policy_name: "test_policy"
policies:
  - name: "test_policy"
    static_rules: {}
    taint_rules: []
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", yaml_content).unwrap();
    let path = temp_file.path();

    let loader = PolicyLoader::from_file(path).unwrap();
    let customer_store = Arc::new(YamlCustomerStore::new(loader.clone()));
    let policy_store = Arc::new(YamlPolicyStore::new(loader));
    let audit_logger = Arc::new(AuditLogger::new(None));

    let auth_state = Arc::new(AuthState {
        customer_store: customer_store as Arc<dyn sentinel_interceptor::api::CustomerStore + Send + Sync>,
        policy_store: policy_store as Arc<dyn sentinel_interceptor::api::PolicyStore + Send + Sync>,
        audit_logger,
        yaml_fallback: None,
    });

    let app_state = create_test_app_state();
    let app = create_router(app_state, Some(auth_state));

    // Health endpoint should bypass auth
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    // Should not be 401 (health endpoint bypasses auth)
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}

