// Real integration tests for authentication

#[path = "common/mod.rs"]
mod common;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use sentinel_interceptor::api::{create_router, AppState};
use sentinel_interceptor::auth::audit_logger::AuditLogger;
use sentinel_interceptor::auth::auth_middleware::AuthState;
use sentinel_interceptor::auth::customer_store::YamlCustomerStore;
use sentinel_interceptor::auth::policy_store::YamlPolicyStore;
use sentinel_interceptor::core::crypto::CryptoSigner;
use sentinel_interceptor::loader::policy_loader::PolicyLoader;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tower::ServiceExt;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use common::*;

fn create_test_app_state() -> AppState {
    let signing_key = SigningKey::generate(&mut OsRng);
    let crypto_signer = Arc::new(CryptoSigner::from_signing_key(signing_key));
    
    let redis_store: Arc<dyn sentinel_interceptor::api::RedisStore + Send + Sync> =
        Arc::new(MockRedisStore::default());
    let policy_cache: Arc<dyn sentinel_interceptor::api::PolicyCache + Send + Sync> =
        Arc::new(MockPolicyCache);
    let evaluator: Arc<dyn sentinel_interceptor::api::PolicyEvaluator + Send + Sync> =
        Arc::new(MockPolicyEvaluator::default());
    let proxy_client: Arc<dyn sentinel_interceptor::api::ProxyClient + Send + Sync> =
        Arc::new(MockProxyClient {
            response: Ok(serde_json::json!({"result": "success"})),
            should_delay: false,
        });
    let customer_store: Arc<dyn sentinel_interceptor::api::CustomerStore + Send + Sync> =
        Arc::new(MockCustomerStore::default());
    let policy_store: Arc<dyn sentinel_interceptor::api::PolicyStore + Send + Sync> =
        Arc::new(MockPolicyStore::default());
    
    let mut tool_classes = HashMap::new();
    tool_classes.insert("read_file".to_string(), vec!["FILE_OPERATION".to_string()]);
    let tool_registry: Arc<dyn sentinel_interceptor::api::ToolRegistry + Send + Sync> =
        Arc::new(MockToolRegistry { tool_classes, should_fail: false });
    
    let config = Arc::new(sentinel_interceptor::config::Config::test_config());
    
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
async fn test_auth_middleware_missing_api_key_returns_401() {
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
    let loader_arc = Arc::new(loader.clone());
    let customer_store = Arc::new(YamlCustomerStore::new(loader.clone()));
    let policy_store = Arc::new(YamlPolicyStore::new(loader));
    let audit_logger = Arc::new(AuditLogger::new(None));

    let auth_state = Arc::new(AuthState {
        customer_store: customer_store as Arc<dyn sentinel_interceptor::api::CustomerStore + Send + Sync>,
        policy_store: policy_store as Arc<dyn sentinel_interceptor::api::PolicyStore + Send + Sync>,
        audit_logger,
        yaml_fallback: Some(loader_arc),
    });

    let app_state = create_test_app_state();
    let app = create_router(&app_state, Some(auth_state)).with_state(app_state.clone());

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
async fn test_auth_middleware_invalid_api_key_returns_401() {
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
    let loader_arc = Arc::new(loader.clone());
    let customer_store = Arc::new(YamlCustomerStore::new(loader.clone()));
    let policy_store = Arc::new(YamlPolicyStore::new(loader));
    let audit_logger = Arc::new(AuditLogger::new(None));

    let auth_state = Arc::new(AuthState {
        customer_store: customer_store as Arc<dyn sentinel_interceptor::api::CustomerStore + Send + Sync>,
        policy_store: policy_store as Arc<dyn sentinel_interceptor::api::PolicyStore + Send + Sync>,
        audit_logger,
        yaml_fallback: Some(loader_arc),
    });

    let app_state = create_test_app_state();
    let app = create_router(&app_state, Some(auth_state)).with_state(app_state.clone());

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
async fn test_auth_middleware_health_endpoint_bypasses_auth() {
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
    let loader_arc = Arc::new(loader.clone());
    let customer_store = Arc::new(YamlCustomerStore::new(loader.clone()));
    let policy_store = Arc::new(YamlPolicyStore::new(loader));
    let audit_logger = Arc::new(AuditLogger::new(None));

    let auth_state = Arc::new(AuthState {
        customer_store: customer_store as Arc<dyn sentinel_interceptor::api::CustomerStore + Send + Sync>,
        policy_store: policy_store as Arc<dyn sentinel_interceptor::api::PolicyStore + Send + Sync>,
        audit_logger,
        yaml_fallback: Some(loader_arc),
    });

    let app_state = create_test_app_state();
    let app = create_router(&app_state, Some(auth_state)).with_state(app_state.clone());

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

