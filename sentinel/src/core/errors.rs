// Domain error types - Secure error handling with no information disclosure

use thiserror::Error;

/// Main error type for the interceptor
#[derive(Error, Debug)]
pub enum InterceptorError {
    /// Invalid API key (HTTP 401)
    #[error("Invalid API Key")]
    InvalidApiKey,

    /// Authentication error (HTTP 401)
    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    /// Validation error (HTTP 400)
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Infrastructure error (HTTP 503)
    #[error("Infrastructure error: {0}")]
    InfrastructureError(String),

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

    /// Dependency failure (HTTP 503)
    /// Used when a downstream service (Redis, DB, MCP Agent) is unavailable
    #[error("Dependency failure ({service}): {error}")]
    DependencyFailure { service: String, error: String },

    /// Transient error (HTTP 503)
    /// Used for retryable conditions like timeouts or temporary network issues
    #[error("Transient error: {0}")]
    TransientError(String),

    /// I/O Error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Process Management Error
    #[error("Process error: {0}")]
    ProcessError(String),
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

    /// Failed to generate random bytes
    #[error("Failed to generate random bytes")]
    RandomError,
}

impl InterceptorError {
    /// Get user-friendly error message.
    pub fn user_message(&self) -> String {
        match self {
            InterceptorError::InvalidApiKey => "Invalid API Key".to_string(),
            InterceptorError::AuthenticationError(reason) => {
                format!("Authentication failed: {}", reason)
            }
            InterceptorError::ValidationError(reason) => format!("Validation failed: {}", reason),
            InterceptorError::InfrastructureError(_) => "Service unavailable".to_string(),
            InterceptorError::PolicyViolation(reason) => format!("Policy violation: {}", reason),
            InterceptorError::CryptoError(_) => "Internal error".to_string(),
            InterceptorError::McpProxyError(_) => "Service unavailable".to_string(),
            InterceptorError::ConfigurationError(_) => "Internal error".to_string(),
            InterceptorError::StateError(_) => "Internal error".to_string(),
            InterceptorError::DependencyFailure { .. } => "Service unavailable".to_string(),
            InterceptorError::TransientError(_) => "Service briefly unavailable".to_string(),
            InterceptorError::IoError(_) => "Internal system error".to_string(),
            InterceptorError::ProcessError(_) => "Internal process error".to_string(),
        }
    }
}
