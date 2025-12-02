// Domain error types - Secure error handling with no information disclosure

use thiserror::Error;

/// Main error type for the interceptor
#[derive(Error, Debug)]
pub enum InterceptorError {
    /// Invalid API key (HTTP 401)
    #[error("Invalid API Key")]
    InvalidApiKey,

    /// Policy violation (HTTP 403)
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Cryptographic error (HTTP 500)
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] CryptoError),

    /// MCP proxy error (HTTP 502)
    #[error("MCP proxy error: {0}")]
    McpProxyError(String),

    /// Configuration error (HTTP 500)
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// State management error (HTTP 500)
    #[error("State error: {0}")]
    StateError(String),
}

/// Cryptographic operation errors
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Failed to load private key
    #[error("Failed to load private key: {0}")]
    KeyLoadError(String),

    /// Failed to sign token
    #[error("Failed to sign token: {0}")]
    SigningError(String),

    /// Failed to canonicalize JSON
    #[error("Failed to canonicalize JSON: {0}")]
    CanonicalizationError(String),

    /// Failed to hash parameters
    #[error("Failed to hash parameters: {0}")]
    HashingError(String),
}

impl InterceptorError {
    /// Get HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            InterceptorError::InvalidApiKey => 401,
            InterceptorError::PolicyViolation(_) => 403,
            InterceptorError::CryptoError(_) => 500,
            InterceptorError::McpProxyError(_) => 502,
            InterceptorError::ConfigurationError(_) => 500,
            InterceptorError::StateError(_) => 500,
        }
    }

    /// Get user-friendly error message (no sensitive information)
    pub fn user_message(&self) -> String {
        match self {
            InterceptorError::InvalidApiKey => "Invalid API Key".to_string(),
            InterceptorError::PolicyViolation(reason) => format!("Policy violation: {}", reason),
            InterceptorError::CryptoError(_) => "Internal error".to_string(),
            InterceptorError::McpProxyError(_) => "Service unavailable".to_string(),
            InterceptorError::ConfigurationError(_) => "Internal error".to_string(),
            InterceptorError::StateError(_) => "Internal error".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
