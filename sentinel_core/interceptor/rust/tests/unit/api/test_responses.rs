// Unit tests for API response types

use axum::{
    http::StatusCode,
    response::IntoResponse,
};
use sentinel_interceptor::api::responses::*;
use sentinel_interceptor::core::errors::*;

#[test]
fn test_proxy_response_serialization() {
    let response = ProxyResponse {
        result: serde_json::json!({"output": "success"}),
    };
    
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("output"));
    assert!(json.contains("success"));
}

#[test]
fn test_error_response_serialization() {
    let response = ErrorResponse {
        error: "Test error".to_string(),
        request_id: None,
    };
    
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("Test error"));
    assert!(!json.contains("request_id")); // Should be omitted when None
}

#[test]
fn test_error_response_with_request_id() {
    let response = ErrorResponse {
        error: "Test error".to_string(),
        request_id: Some("req-123".to_string()),
    };
    
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("Test error"));
    assert!(json.contains("req-123"));
}

#[test]
fn test_health_response_serialization() {
    let response = HealthResponse {
        status: "healthy".to_string(),
        redis: "connected".to_string(),
        database: None,
    };
    
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("healthy"));
    assert!(json.contains("connected"));
    assert!(!json.contains("database")); // Should be omitted when None
}

#[test]
fn test_health_response_with_database() {
    let response = HealthResponse {
        status: "healthy".to_string(),
        redis: "connected".to_string(),
        database: Some("connected".to_string()),
    };
    
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("healthy"));
    assert!(json.contains("connected"));
    assert!(json.contains("database"));
}

#[test]
fn test_api_error_new() {
    let err = ApiError::new(
        StatusCode::BAD_REQUEST,
        "Invalid request".to_string(),
    );
    
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(err.message, "Invalid request");
    assert_eq!(err.request_id, None);
}

#[test]
fn test_api_error_with_request_id() {
    let err = ApiError::with_request_id(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Server error".to_string(),
        "req-456".to_string(),
    );
    
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(err.message, "Server error");
    assert_eq!(err.request_id, Some("req-456".to_string()));
}

#[test]
fn test_api_error_from_interceptor_error() {
    let interceptor_err = InterceptorError::InvalidApiKey;
    let api_err = ApiError::from_interceptor_error(interceptor_err);
    
    assert_eq!(api_err.status, StatusCode::UNAUTHORIZED);
    assert_eq!(api_err.message, "Invalid API Key");
    assert_eq!(api_err.request_id, None);
}

#[test]
fn test_api_error_from_interceptor_error_policy_violation() {
    let interceptor_err = InterceptorError::PolicyViolation("Tool forbidden".to_string());
    let api_err = ApiError::from_interceptor_error(interceptor_err);
    
    assert_eq!(api_err.status, StatusCode::FORBIDDEN);
    assert_eq!(api_err.message, "Policy violation: Tool forbidden");
    assert_eq!(api_err.request_id, None);
}

#[test]
fn test_api_error_from_interceptor_error_crypto_error() {
    let crypto_err = CryptoError::KeyLoadError("File not found".to_string());
    let interceptor_err = InterceptorError::CryptoError(crypto_err);
    let api_err = ApiError::from_interceptor_error(interceptor_err);
    
    assert_eq!(api_err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(api_err.message, "Internal error"); // Generic message for crypto errors
    assert_eq!(api_err.request_id, None);
}

#[test]
fn test_api_error_from_interceptor_error_mcp_proxy_error() {
    let interceptor_err = InterceptorError::McpProxyError("Connection failed".to_string());
    let api_err = ApiError::from_interceptor_error(interceptor_err);
    
    assert_eq!(api_err.status, StatusCode::BAD_GATEWAY);
    assert_eq!(api_err.message, "Service unavailable");
    assert_eq!(api_err.request_id, None);
}

#[test]
fn test_api_error_from_interceptor_error_with_id() {
    let interceptor_err = InterceptorError::InvalidApiKey;
    let api_err = ApiError::from_interceptor_error_with_id(
        interceptor_err,
        "req-789".to_string(),
    );
    
    assert_eq!(api_err.status, StatusCode::UNAUTHORIZED);
    assert_eq!(api_err.message, "Invalid API Key");
    assert_eq!(api_err.request_id, Some("req-789".to_string()));
}

#[test]
fn test_api_error_from_trait() {
    let interceptor_err = InterceptorError::PolicyViolation("Test".to_string());
    let api_err: ApiError = interceptor_err.into();
    
    assert_eq!(api_err.status, StatusCode::FORBIDDEN);
    assert_eq!(api_err.message, "Policy violation: Test");
}

#[test]
fn test_api_error_into_response() {
    let api_err = ApiError::new(
        StatusCode::NOT_FOUND,
        "Resource not found".to_string(),
    );
    
    let response = api_err.into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    
    // Verify response body contains error message
    // Note: We can't easily test the body without more complex setup,
    // but we can verify the status code is correct
}

#[test]
fn test_api_error_into_response_with_request_id() {
    let api_err = ApiError::with_request_id(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Server error".to_string(),
        "req-999".to_string(),
    );
    
    let response = api_err.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn test_api_error_status_code_mapping() {
    // Test all error types map to correct status codes
    let test_cases = vec![
        (InterceptorError::InvalidApiKey, StatusCode::UNAUTHORIZED),
        (InterceptorError::PolicyViolation("test".to_string()), StatusCode::FORBIDDEN),
        (InterceptorError::CryptoError(CryptoError::KeyLoadError("test".to_string())), StatusCode::INTERNAL_SERVER_ERROR),
        (InterceptorError::McpProxyError("test".to_string()), StatusCode::BAD_GATEWAY),
        (InterceptorError::ConfigurationError("test".to_string()), StatusCode::INTERNAL_SERVER_ERROR),
        (InterceptorError::StateError("test".to_string()), StatusCode::INTERNAL_SERVER_ERROR),
    ];
    
    for (interceptor_err, expected_status) in test_cases {
        let api_err = ApiError::from_interceptor_error(interceptor_err);
        assert_eq!(api_err.status, expected_status, "Status code mismatch");
    }
}

#[test]
fn test_api_error_user_message_security() {
    // Verify that sensitive information is not exposed in user messages
    let crypto_err = CryptoError::KeyLoadError("/app/secrets/private_key.pem not found".to_string());
    let interceptor_err = InterceptorError::CryptoError(crypto_err);
    let api_err = ApiError::from_interceptor_error(interceptor_err);
    
    // Should not contain file paths
    assert!(!api_err.message.contains("/app/secrets"));
    assert!(!api_err.message.contains("private_key.pem"));
    assert_eq!(api_err.message, "Internal error");
}

#[test]
fn test_api_error_policy_violation_message_preserved() {
    // Policy violation messages should be preserved (they're user-facing)
    let interceptor_err = InterceptorError::PolicyViolation("Tool 'delete_file' is forbidden".to_string());
    let api_err = ApiError::from_interceptor_error(interceptor_err);
    
    assert!(api_err.message.contains("Policy violation"));
    assert!(api_err.message.contains("delete_file"));
}

