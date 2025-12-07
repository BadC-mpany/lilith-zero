use sentinel_interceptor::api::{create_router, AppState};
use sentinel_interceptor::core::crypto::CryptoSigner;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use tower::ServiceExt;
use std::sync::Arc;
use std::collections::HashMap;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[path = "common/mod.rs"]
mod common;
use common::*;

fn create_failing_app_state(fail_taints: bool, fail_history: bool) -> AppState {
    let mut redis_store = MockRedisStore::default();
    redis_store.get_taints_should_fail = fail_taints;
    redis_store.get_history_should_fail = fail_history;

    let signing_key = SigningKey::generate(&mut OsRng);
    let crypto_signer = Arc::new(CryptoSigner::from_signing_key(signing_key));
    
    // ... other mocks ...
    let policy_cache = Arc::new(MockPolicyCache);
    let evaluator = Arc::new(MockPolicyEvaluator::default());
    let proxy_client = Arc::new(MockProxyClient::default());
    let customer_store = Arc::new(MockCustomerStore::default());
    let policy_store = Arc::new(MockPolicyStore::default());
    
    let mut tool_classes = HashMap::new();
    tool_classes.insert("read_file".to_string(), vec!["FILE_OPERATION".to_string()]);
    let tool_registry = Arc::new(MockToolRegistry { tool_classes, should_fail: false });
    
    let config = Arc::new(sentinel_interceptor::config::Config::test_config());
    
    AppState {
        crypto_signer,
        redis_store: Arc::new(redis_store),
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
async fn test_proxy_execute_fails_closed_when_redis_taints_fail() {
    let app_state = create_failing_app_state(true, false);
    // Note: We skip auth middleware by not providing it, but we need to inject extensions manually 
    // OR just use the fact that without extensions it fails differently?
    // Actually, proxy_execute_handler extracts Extension<CustomerConfig> and Extension<PolicyDefinition>.
    // To test the handler logic, we need to supply these.
    
    // However, create_router only applies auth middleware if provided. 
    // If not provided, the extensions won't be there and handler will panic or return 500?
    // Axum extractors that fail usually return 500 or 400.
    // We need to inject the extensions to reach the Redis call.
    // The easiest way is to use `create_router` with NO auth middleware, but inject extensions in the request?
    // No, Extension extractor looks for request extensions.
    
    let app = create_router(&app_state, None).with_state(app_state.clone());
    
    let request_body = serde_json::json!({
        "session_id": "test-session",
        "tool_name": "read_file",
        "args": {}
    });

    // Create request with extensions
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/proxy-execute")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    // Inject required extensions
    request.extensions_mut().insert(create_test_customer_config("owner", "policy"));
    request.extensions_mut().insert(create_test_policy("policy"));

    let response = app.oneshot(request).await.unwrap();
    
    // SHOULD return 503 Service Unavailable (mapped from StateError)
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "Should fail closed with 503");
}
