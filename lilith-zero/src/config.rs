// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::engine_core::errors::InterceptorError;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

/// Controls the enforcement posture of the security middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SecurityLevel {
    /// Log policy violations but allow all requests through.
    ///
    /// Useful for initial deployment and policy tuning without disrupting agents.
    AuditOnly,
    /// Enforce policy strictly — deny requests that violate policy or have no loaded policy.
    ///
    /// This is the production-safe default (fail-closed).
    BlockParams,
}

impl SecurityLevel {
    /// Parse a string to a [`SecurityLevel`], defaulting to [`SecurityLevel::BlockParams`] on
    /// unrecognized input (fail-safe: unknown level → strict enforcement).
    pub fn parse_safe(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "audit_only" | "low" => SecurityLevel::AuditOnly,
            "full_isolation" | "high" => SecurityLevel::BlockParams,
            _ => SecurityLevel::BlockParams,
        }
    }
}

/// Runtime security flags derived from [`SecurityLevel`].
pub struct SecurityConfig {
    /// Whether incoming tool requests must carry a valid HMAC session token.
    pub session_validation: bool,
    /// Whether tool-response content should be wrapped in spotlighting delimiters.
    pub spotlighting: bool,
}

/// Top-level runtime configuration for the middleware.
///
/// Populated from environment variables via [`Config::from_env`] or built programmatically.
/// All fields are `pub` to allow test fixtures to override individual settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the YAML policy file; `None` means no policy loaded (fail-closed unless
    /// [`SecurityLevel::AuditOnly`]).
    pub policies_yaml_path: Option<PathBuf>,
    /// Tracing filter string, e.g. `"info"` or `"lilith_zero=debug"`.
    pub log_level: String,
    /// Log output format: `"json"` for structured logging or `"text"` for human-readable.
    pub log_format: String,
    /// Identifier for the policy owner / deployment (informational only).
    pub owner: String,
    /// Expected JWT audience values; when set, `initialize` handshakes must carry a valid token.
    pub expected_audience: Option<Vec<String>>,
    /// Enforcement posture — see [`SecurityLevel`].
    pub security_level: SecurityLevel,
    /// MCP protocol version to advertise to the upstream server.
    pub mcp_version: String,
    /// HMAC secret for JWT audience validation; required when `expected_audience` is set.
    pub jwt_secret: Option<String>,
    /// When `true`, auto-inject the lethal-trifecta EXFILTRATION blocking rule.
    pub protect_lethal_trifecta: bool,
}

impl Config {
    /// Build a [`Config`] from environment variables.
    ///
    /// Falls back to safe defaults for missing variables. Returns an error only if the
    /// environment contains values that cannot be parsed at all.
    pub fn from_env() -> Result<Self, InterceptorError> {
        Ok(Self {
            policies_yaml_path: env::var(
                crate::engine_core::constants::config::ENV_POLICIES_YAML_PATH,
            )
            .ok()
            .map(PathBuf::from),
            log_level: env::var(crate::engine_core::constants::config::ENV_LOG_LEVEL)
                .unwrap_or_else(|_| "info".to_string()),
            log_format: env::var(crate::engine_core::constants::config::ENV_LOG_FORMAT)
                .unwrap_or_else(|_| "text".to_string()),
            owner: env::var(crate::engine_core::constants::config::ENV_OWNER)
                .unwrap_or_else(|_| "unknown".to_string()),
            expected_audience: env::var(
                crate::engine_core::constants::config::ENV_EXPECTED_AUDIENCE,
            )
            .ok()
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect()),
            security_level: SecurityLevel::parse_safe(
                &env::var(crate::engine_core::constants::config::ENV_SECURITY_LEVEL)
                    .unwrap_or_else(|_| "medium".to_string()),
            ),
            mcp_version: env::var(crate::engine_core::constants::config::ENV_MCP_VERSION)
                .unwrap_or_else(|_| "2024-11-05".to_string()),
            jwt_secret: env::var("LILITH_ZERO_JWT_SECRET").ok(),
            protect_lethal_trifecta: env::var("LILITH_ZERO_FORCE_LETHAL_TRIFECTA")
                .map(|v| v.to_lowercase() == "true" || v == "1")
                .unwrap_or(false),
        })
    }

    /// Return the concrete security flags for the current [`SecurityLevel`].
    pub fn security_level_config(&self) -> SecurityConfig {
        match self.security_level {
            SecurityLevel::AuditOnly => SecurityConfig {
                session_validation: true,
                spotlighting: false,
            },
            SecurityLevel::BlockParams => SecurityConfig {
                session_validation: true,
                spotlighting: true,
            },
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            policies_yaml_path: None,
            log_level: "info".to_string(),
            log_format: "text".to_string(),
            owner: "unknown".to_string(),
            expected_audience: None,
            security_level: SecurityLevel::BlockParams,
            mcp_version: "2024-11-05".to_string(),
            jwt_secret: None,
            protect_lethal_trifecta: false,
        }
    }
}
