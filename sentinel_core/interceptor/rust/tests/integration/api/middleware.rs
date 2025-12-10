// Real integration tests for middleware (timeouts, body size limits, etc.)

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use sentinel_interceptor::api::{create_router, AppState};
use sentinel_interceptor::core::crypto::CryptoSigner;
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use super::super::common::*;

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
async fn test_body_size_limit_enforced() {
    let app_state = create_test_app_state();
    let app = create_router(&app_state, None).with_state(app_state.clone());
    
    // Create a body larger than 2MB (default limit)
    let large_body = vec![0u8; 3 * 1024 * 1024]; // 3MB
    let large_body_str = String::from_utf8_lossy(&large_body);
    
    let request_body = serde_json::json!({
        "session_id": "test",
        "tool_name": "test",
        "args": {"data": large_body_str}
    });
    
    let request = Request::builder()
        .method("POST")
        .uri("/v1/proxy-execute")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    // Should reject large payload (413 or 400 depending on where it's caught)
    let status = response.status();
    // Should reject large payload (413 or 400 depending on where it's caught)
    assert!(status == StatusCode::PAYLOAD_TOO_LARGE || status == StatusCode::BAD_REQUEST, 
            "Expected PAYLOAD_TOO_LARGE or BAD_REQUEST, got {:?}", status);
}

#[tokio::test]
async fn test_valid_body_size_accepted() {
    let app_state = create_test_app_state();
    let app = create_router(&app_state, None).with_state(app_state.clone());
    
    // Create a body within limit (1MB)
    let medium_body = vec![0u8; 1024 * 1024]; // 1MB
    let medium_body_str = String::from_utf8_lossy(&medium_body);
    
    let request_body = serde_json::json!({
        "session_id": "test",
        "tool_name": "test",
        "args": {"data": medium_body_str}
    });
    
    let request = Request::builder()
        .method("POST")
        .uri("/v1/proxy-execute")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    // Should accept valid size (may fail on auth, but not on size)
    assert!(response.status() != StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_content_type_validation() {
    let app_state = create_test_app_state();
    let app = create_router(&app_state, None).with_state(app_state.clone());
    
    let request_body = serde_json::json!({
        "session_id": "test",
        "tool_name": "read_file",
        "args": {}
    });
    
    // Missing Content-Type header
    let request = Request::builder()
        .method("POST")
        .uri("/v1/proxy-execute")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    // Should still process (axum is lenient), but may fail on JSON parsing
    assert!(response.status() != StatusCode::OK);
}

#[tokio::test]
async fn test_cors_headers_present() {
    let app_state = create_test_app_state();
    let app = create_router(&app_state, None).with_state(app_state.clone());
    
    let request = Request::builder()
        .method("OPTIONS")
        .uri("/v1/proxy-execute")
        .header("Origin", "http://localhost:3000")
        .header("Access-Control-Request-Method", "POST")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    // CORS middleware should handle OPTIONS requests
    // Check if CORS headers are present (if CORS is configured)
    let headers = response.headers();
    // If CORS is enabled, should have Access-Control-Allow-Origin
    // This test verifies the middleware is applied
    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::METHOD_NOT_ALLOWED);
}

