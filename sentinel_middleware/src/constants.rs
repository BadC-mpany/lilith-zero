//! Sentinel Middleware Constants - Single source of truth for all configuration values.
//!
//! This module centralizes all magic numbers, error codes, and configuration
//! constants to ensure consistency and maintainability.

/// JSON-RPC 2.0 Error Codes
pub mod jsonrpc {
    /// Security block by Sentinel policy (custom code)
    pub const ERROR_SECURITY_BLOCK: i32 = -32000;
    /// Authentication/session error (custom code)
    pub const ERROR_AUTH: i32 = -32001;
    /// Method not found (standard JSON-RPC)
    pub const ERROR_METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid request (standard JSON-RPC)
    pub const ERROR_INVALID_REQUEST: i32 = -32600;
    /// Internal error (standard JSON-RPC)
    pub const ERROR_INTERNAL: i32 = -32603;
    /// Parse error (standard JSON-RPC)
    pub const ERROR_PARSE: i32 = -32700;
}

/// Cryptographic constants
pub mod crypto {
    /// HMAC-SHA256 secret key length in bytes
    pub const SECRET_KEY_LENGTH: usize = 32;
    /// Session ID format version
    pub const SESSION_ID_VERSION: &str = "1";
}

/// Spotlighting delimiters for prompt injection defense
pub mod spotlight {
    /// Start delimiter prefix
    pub const DATA_START_PREFIX: &str = "<<<SENTINEL_DATA_START:";
    /// End delimiter prefix
    pub const DATA_END_PREFIX: &str = "<<<SENTINEL_DATA_END:";
    /// Delimiter suffix
    pub const DELIMITER_SUFFIX: &str = ">>>";
    /// Random ID length for spotlighting delimiters
    pub const RANDOM_ID_LENGTH: usize = 8;
}

/// Policy evaluation constants
pub mod policy {
    /// Action value for allowing a tool
    pub const ACTION_ALLOW: &str = "ALLOW";
    /// Action value for denying a tool
    pub const ACTION_DENY: &str = "DENY";
    /// Default policy ID when no policy is loaded
    pub const DEFAULT_POLICY_ID: &str = "default";
    /// Default policy name
    pub const DEFAULT_POLICY_NAME: &str = "Permissive Default";
}

/// Session management
pub mod session {
    /// Environment variable for session ID output
    pub const SESSION_ID_ENV_PREFIX: &str = "SENTINEL_SESSION_ID=";
    /// Session ID field name in JSON-RPC params
    pub const SESSION_ID_PARAM: &str = "_sentinel_session_id";
}
