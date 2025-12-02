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
