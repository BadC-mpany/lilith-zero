use crate::core::errors::InterceptorError;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityLevel {
    AuditOnly,
    BlockParams,
    FullIsolation,
}

impl SecurityLevel {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "audit_only" | "low" => SecurityLevel::AuditOnly,
            "full_isolation" | "high" => SecurityLevel::FullIsolation,
            "block_params" | "medium" | _ => SecurityLevel::BlockParams,
        }
    }
}

pub struct SecurityConfig {
    pub session_validation: bool,
    pub spotlighting: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub policies_yaml_path: Option<PathBuf>,
    pub log_level: String,
    pub log_format: String, // "json" or "text"
    pub owner: String,
    pub expected_audience: Option<Vec<String>>,
    pub security_level: SecurityLevel,
    pub mcp_version: String,
}

impl Config {
    pub fn from_env() -> Result<Self, InterceptorError> {
        Ok(Self {
            policies_yaml_path: env::var(crate::constants::config::ENV_POLICIES_YAML_PATH).ok().map(PathBuf::from),
            log_level: env::var(crate::constants::config::ENV_LOG_LEVEL).unwrap_or_else(|_| "info".to_string()),
            log_format: env::var(crate::constants::config::ENV_LOG_FORMAT).unwrap_or_else(|_| "text".to_string()),
            owner: env::var(crate::constants::config::ENV_OWNER).unwrap_or_else(|_| "unknown".to_string()),
            expected_audience: env::var(crate::constants::config::ENV_EXPECTED_AUDIENCE)
                .ok()
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect()),
            security_level: SecurityLevel::from_str(
                &env::var(crate::constants::config::ENV_SECURITY_LEVEL).unwrap_or_else(|_| "medium".to_string())
            ),
            mcp_version: env::var(crate::constants::config::ENV_MCP_VERSION).unwrap_or_else(|_| "2024-11-05".to_string()),
        })
    }

    pub fn security_level_config(&self) -> SecurityConfig {
        match self.security_level {
            SecurityLevel::AuditOnly => SecurityConfig {
                // Plan said: AuditOnly = Log everything, allow everything.
                // But session ID validation is fundamental to knowing WHO it is.
                session_validation: true, 
                spotlighting: false,
            },
            SecurityLevel::BlockParams => SecurityConfig {
                session_validation: true,
                spotlighting: true,
            },
            SecurityLevel::FullIsolation => SecurityConfig {
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
        }
    }
}
