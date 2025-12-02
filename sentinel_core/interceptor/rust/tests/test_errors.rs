// Unit tests for error types

use sentinel_interceptor::core::errors::*;

#[test]
fn test_error_conversion() {
    let crypto_err = CryptoError::KeyLoadError("File not found".to_string());
    let interceptor_err: InterceptorError = crypto_err.into();
    
    match interceptor_err {
        InterceptorError::CryptoError(CryptoError::KeyLoadError(_)) => (),
        _ => panic!("Expected CryptoError::KeyLoadError"),
    }
}

#[test]
fn test_status_codes() {
    assert_eq!(InterceptorError::InvalidApiKey.status_code(), 401);
    assert_eq!(InterceptorError::PolicyViolation("test".to_string()).status_code(), 403);
    assert_eq!(InterceptorError::CryptoError(CryptoError::KeyLoadError("test".to_string())).status_code(), 500);
    assert_eq!(InterceptorError::McpProxyError("test".to_string()).status_code(), 502);
}

#[test]
fn test_user_messages_no_sensitive_data() {
    // Verify that user messages don't expose sensitive information
    let err = InterceptorError::CryptoError(CryptoError::KeyLoadError("File /app/secrets/key.pem not found".to_string()));
    let user_msg = err.user_message();
    
    // Should not contain file path
    assert!(!user_msg.contains("/app/secrets"));
    assert_eq!(user_msg, "Internal error");
}

#[test]
fn test_policy_violation_message_preserved() {
    let err = InterceptorError::PolicyViolation("Tool 'delete_db' is forbidden".to_string());
    let user_msg = err.user_message();
    
    // Policy violation messages are user-facing and should be preserved
    assert!(user_msg.contains("Policy violation"));
    assert!(user_msg.contains("delete_db"));
}

