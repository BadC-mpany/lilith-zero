// Copyright 2026 BadCompany
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::engine_core::errors::InterceptorError;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SecurityLevel {
    AuditOnly,
    BlockParams,
}

impl SecurityLevel {
    pub fn parse_safe(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "audit_only" | "low" => SecurityLevel::AuditOnly,
            "full_isolation" | "high" => SecurityLevel::BlockParams,
            _ => SecurityLevel::BlockParams,
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
    pub jwt_secret: Option<String>,
    pub protect_lethal_trifecta: bool,
}

impl Config {
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
