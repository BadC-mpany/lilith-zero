use crate::core::errors::InterceptorError;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub policies_yaml_path: Option<PathBuf>,
    pub log_level: String,
    pub log_format: String, // "json" or "text"
}

impl Config {
    pub fn from_env() -> Result<Self, InterceptorError> {
        // dotenv support removed for stdio middleware cleanliness

        Ok(Self {
            policies_yaml_path: env::var("POLICIES_YAML_PATH").ok().map(PathBuf::from),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            log_format: env::var("LOG_FORMAT").unwrap_or_else(|_| "text".to_string()),
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            policies_yaml_path: None,
            log_level: "info".to_string(),
            log_format: "text".to_string(),
        }
    }
}
