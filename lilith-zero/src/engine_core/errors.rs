// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use thiserror::Error;

/// Top-level error type for all middleware operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum InterceptorError {
    /// The provided API key is not valid.
    #[error("Invalid API Key")]
    InvalidApiKey,

    /// Authentication failed for the given reason.
    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    /// A request or policy parameter failed validation.
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// An infrastructure dependency is unavailable.
    #[error("Infrastructure error: {0}")]
    InfrastructureError(String),

    /// A request was rejected due to a security policy violation.
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// A cryptographic operation failed.
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] CryptoError),

    /// The MCP proxy layer encountered an error.
    #[error("MCP proxy error: {0}")]
    McpProxyError(String),

    /// The middleware configuration is invalid or incomplete.
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// An internal state invariant was violated.
    #[error("State error: {0}")]
    StateError(String),

    /// A downstream service dependency failed.
    #[error("Dependency failure ({service}): {error}")]
    DependencyFailure {
        /// Name of the failing service.
        service: String,
        /// Description of the failure.
        error: String,
    },

    /// A transient, retriable error occurred.
    #[error("Transient error: {0}")]
    TransientError(String),

    /// An I/O operation failed.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// A subprocess operation failed.
    #[error("Process error: {0}")]
    ProcessError(String),
}

/// Errors arising from cryptographic operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CryptoError {
    /// The private key could not be loaded.
    #[error("Failed to load private key: {0}")]
    KeyLoadError(String),

    /// Token signing failed.
    #[error("Failed to sign token: {0}")]
    SigningError(String),

    /// JSON canonicalization for signing failed.
    #[error("Failed to canonicalize JSON: {0}")]
    CanonicalizationError(String),

    /// Hashing a parameter set failed.
    #[error("Failed to hash parameters: {0}")]
    HashingError(String),

    /// The OS random-number generator returned an error.
    #[error("Failed to generate random bytes")]
    RandomError,
}

impl InterceptorError {
    /// Returns a safe, user-facing error message that does not leak internal details.
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
