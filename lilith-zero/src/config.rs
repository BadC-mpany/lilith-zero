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

/// Controls how tool-description pin violations are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinMode {
    /// Log pin violations and allow the `tools/list` response through.
    Audit,
    /// Block the `tools/list` response and return a security error when a pin violation is detected.
    Enforce,
}

impl PinMode {
    /// Parse a string to a [`PinMode`], defaulting to [`PinMode::Audit`] on unrecognized input.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "enforce" | "block" => PinMode::Enforce,
            _ => PinMode::Audit,
        }
    }
}

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
    /// Whether policy violations should result in a hard `Deny`.
    ///
    /// `false` in [`SecurityLevel::AuditOnly`] (log and allow); `true` in
    /// [`SecurityLevel::BlockParams`] (deny, fail-closed).
    pub block_on_violation: bool,
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
    /// Path to the tool-description pin file.  `None` = in-memory pins only (reset each session).
    pub pin_file: Option<PathBuf>,
    /// Whether pin violations should block the response or just be logged.
    pub pin_mode: PinMode,
    /// URL of an upstream HTTP MCP server (e.g. `http://localhost:8080/mcp`).
    ///
    /// When set, Lilith proxies to this HTTP endpoint instead of spawning a child
    /// process.  Mutually exclusive with `upstream_cmd` at runtime.
    pub upstream_http_url: Option<String>,

    /// Command string for the upstream stdio child process (e.g. `"python -u server.py"`).
    ///
    /// Set by `--upstream-cmd` / `-u`.  Mutually exclusive with `upstream_http_url`.
    pub upstream_cmd: Option<String>,

    /// When `true`, log the full RAW_WEBHOOK_PAYLOAD in the webhook server.
    pub webhook_debug: bool,

    /// When `true`, enable a minimal, high-signal logging mode focused on Lilith's decisions.
    pub lean_logs: bool,

    /// Directory for persistent session storage in webhook mode. Taints, history, and rate-limit
    /// counters are persisted to disk per conversation_id. Default: `~/.lilith/sessions`.
    /// Used by [`PersistenceLayer`] to load/save session state across webhook restarts.
    pub session_storage_dir: PathBuf,

    /// Session time-to-live in seconds. Sessions older than this are deleted during cleanup.
    /// Default: 86400 (24 hours). Set to 0 to disable automatic cleanup.
    /// This is configurable (not hardcoded) to allow ops teams to tune retention.
    pub session_ttl_secs: u64,
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
            pin_file: env::var(crate::engine_core::constants::config::ENV_PIN_FILE)
                .ok()
                .map(PathBuf::from),
            pin_mode: env::var(crate::engine_core::constants::config::ENV_PIN_MODE)
                .as_deref()
                .map(PinMode::parse)
                .unwrap_or(PinMode::Audit),
            upstream_http_url: env::var("LILITH_ZERO_UPSTREAM_HTTP_URL").ok(),
            upstream_cmd: None,
            webhook_debug: env::var("LILITH_ZERO_WEBHOOK_DEBUG")
                .map(|v| v.to_lowercase() == "true" || v == "1")
                .unwrap_or(false),
            lean_logs: env::var("LILITH_ZERO_LEAN_LOGS")
                .map(|v| v.to_lowercase() == "true" || v == "1")
                .unwrap_or(false),
            session_storage_dir: env::var(
                crate::engine_core::constants::config::ENV_SESSION_STORAGE_DIR,
            )
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = env::var("HOME")
                    .or_else(|_| env::var("USERPROFILE"))
                    .unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join(".lilith").join("sessions")
            }),
            session_ttl_secs: env::var(
                crate::engine_core::constants::config::ENV_SESSION_TTL_SECS,
            )
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(86400), // 24 hours default
        })
    }

    /// Return the concrete security flags for the current [`SecurityLevel`].
    pub fn security_level_config(&self) -> SecurityConfig {
        match self.security_level {
            SecurityLevel::AuditOnly => SecurityConfig {
                session_validation: true,
                block_on_violation: false,
            },
            SecurityLevel::BlockParams => SecurityConfig {
                session_validation: true,
                block_on_violation: true,
            },
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
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
            pin_file: None,
            pin_mode: PinMode::Audit,
            upstream_http_url: None,
            upstream_cmd: None,
            webhook_debug: false,
            lean_logs: false,
            session_storage_dir: PathBuf::from(home).join(".lilith").join("sessions"),
            session_ttl_secs: 86400,
        }
    }
}
