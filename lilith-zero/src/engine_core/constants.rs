// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

/// JSON-RPC error codes used in security responses.
pub mod jsonrpc {
    /// Error code returned when a request is blocked by security policy.
    pub const ERROR_SECURITY_BLOCK: i32 = -32000;
    /// Error code returned when authentication or session validation fails.
    pub const ERROR_AUTH: i32 = -32001;
    /// Error code returned when a JSON-RPC method is not found.
    pub const ERROR_METHOD_NOT_FOUND: i32 = -32601;
    /// Error code returned for a malformed JSON-RPC request.
    pub const ERROR_INVALID_REQUEST: i32 = -32600;
    /// Error code returned for internal server errors.
    pub const ERROR_INTERNAL: i32 = -32603;
    /// Error code returned when the JSON payload cannot be parsed.
    pub const ERROR_PARSE: i32 = -32700;
}

/// Cryptographic constants for HMAC session ID generation and validation.
pub mod crypto {
    /// Length in bytes of the ephemeral HMAC secret key.
    pub const SECRET_KEY_LENGTH: usize = 32;
    /// Version prefix embedded in session ID tokens (format: `{version}.{uuid_b64}.{hmac_b64}`).
    pub const SESSION_ID_VERSION: &str = "1";
}

/// Constants for the spotlighting prompt-injection mitigation.
pub mod spotlight {
    /// Prefix string that begins a spotlighted data block.
    pub const DATA_START_PREFIX: &str = "<<<LILITH_ZERO_DATA_START:";
    /// Prefix string that ends a spotlighted data block.
    pub const DATA_END_PREFIX: &str = "<<<LILITH_ZERO_DATA_END:";
    /// Suffix appended after the random identifier in spotlighting delimiters.
    pub const DELIMITER_SUFFIX: &str = ">>>";
    /// Number of random alphanumeric characters used in each spotlighting delimiter.
    pub const RANDOM_ID_LENGTH: usize = 8;
}

/// Constants for policy action strings and default policy identifiers.
pub mod policy {
    /// Static rule action that permits the tool call.
    pub const ACTION_ALLOW: &str = "ALLOW";
    /// Static rule action that denies the tool call.
    pub const ACTION_DENY: &str = "DENY";
    /// Identifier used for the built-in permissive default policy.
    pub const DEFAULT_POLICY_ID: &str = "default";
    /// Human-readable name for the built-in permissive default policy.
    pub const DEFAULT_POLICY_NAME: &str = "Permissive Default";
}

/// Constants for session token passing between the agent and middleware.
pub mod session {
    /// Prefix used when emitting the session ID to stderr during startup.
    pub const SESSION_ID_ENV_PREFIX: &str = "LILITH_ZERO_SESSION_ID=";
    /// JSON parameter key used to carry the session token inside MCP request params.
    pub const SESSION_ID_PARAM: &str = "_lilith_zero_session_id";
}

/// Environment variable names for runtime configuration.
pub mod config {
    /// Path to the YAML policy file.
    pub const ENV_POLICIES_YAML_PATH: &str = "POLICIES_YAML_PATH";
    /// Tracing log level filter string.
    pub const ENV_LOG_LEVEL: &str = "LOG_LEVEL";
    /// Log output format (`"json"` or `"text"`).
    pub const ENV_LOG_FORMAT: &str = "LOG_FORMAT";
    /// Policy owner identifier.
    pub const ENV_OWNER: &str = "LILITH_ZERO_OWNER";
    /// Comma-separated list of expected JWT audience values.
    pub const ENV_EXPECTED_AUDIENCE: &str = "LILITH_ZERO_EXPECTED_AUDIENCE";
    /// Security enforcement level string.
    pub const ENV_SECURITY_LEVEL: &str = "LILITH_ZERO_SECURITY_LEVEL";
    /// MCP protocol version to advertise.
    pub const ENV_MCP_VERSION: &str = "LILITH_ZERO_MCP_VERSION";
}

/// MCP JSON-RPC method name constants.
pub mod methods {
    /// The `initialize` handshake method.
    pub const INITIALIZE: &str = "initialize";
    /// The `tools/list` discovery method.
    pub const TOOLS_LIST: &str = "tools/list";
    /// The `tools/call` invocation method.
    pub const TOOLS_CALL: &str = "tools/call";
}

/// Transport-level size limits.
pub mod limits {
    /// Maximum allowed size of a single MCP message in bytes (10 MiB).
    pub const MAX_MESSAGE_SIZE_BYTES: u64 = 10 * 1024 * 1024;
}
