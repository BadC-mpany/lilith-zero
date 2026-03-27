// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum InterceptorError {
    #[error("Invalid API Key")]
    InvalidApiKey,

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Infrastructure error: {0}")]
    InfrastructureError(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] CryptoError),

    #[error("MCP proxy error: {0}")]
    McpProxyError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("State error: {0}")]
    StateError(String),

    #[error("Dependency failure ({service}): {error}")]
    DependencyFailure { service: String, error: String },

    #[error("Transient error: {0}")]
    TransientError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Process error: {0}")]
    ProcessError(String),
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("Failed to load private key: {0}")]
    KeyLoadError(String),

    #[error("Failed to sign token: {0}")]
    SigningError(String),

    #[error("Failed to canonicalize JSON: {0}")]
    CanonicalizationError(String),

    #[error("Failed to hash parameters: {0}")]
    HashingError(String),

    #[error("Failed to generate random bytes")]
    RandomError,
}

impl InterceptorError {
    pub fn user_message(&self) -> String {
        // Description: Executes the user_message logic.
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
