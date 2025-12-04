// Configuration management

use crate::core::errors::InterceptorError;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

/// Application configuration loaded from environment variables
/// 
/// Supports both database-backed and YAML-based operation modes.
/// All configuration is validated on load with clear error messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    // Server configuration
    pub bind_address: String,
    pub port: u16,
    
    // Redis configuration
    pub redis_url: String,
    
    // Redis connection pool configuration
    pub redis_pool_max_size: u32,
    pub redis_pool_min_idle: u32,
    pub redis_pool_max_lifetime_secs: u64,
    pub redis_pool_idle_timeout_secs: u64,
    
    // Redis timeout configuration (configurable, auto-detects WSL/localhost)
    pub redis_connection_timeout_secs: u64,  // Connection establishment timeout
    pub redis_operation_timeout_secs: u64,   // Individual operation timeout
    
    // Database configuration (optional)
    pub database_url: Option<String>,
    
    // Cryptographic configuration
    pub interceptor_private_key_path: PathBuf,
    
    // Policy and tool registry paths
    pub policies_yaml_path: Option<PathBuf>,
    pub tool_registry_yaml_path: PathBuf,
    
    // MCP Proxy configuration
    pub mcp_proxy_timeout_secs: u64,
    
    // Middleware configuration
    pub request_timeout_secs: u64,
    pub body_size_limit_bytes: usize,
    pub rate_limit_per_minute: u32,
    
    // Logging configuration
    pub log_level: String,
    pub log_format: String, // "json" or "text"
}

impl Config {
    /// Load configuration from environment variables
    /// 
    /// Supports `.env` file loading in development (via dotenv crate).
    /// Validates all required fields and file paths.
    /// 
    /// # Returns
    /// * `Result<Self, InterceptorError>` - Config instance or validation error
    pub fn from_env() -> Result<Self, InterceptorError> {
        // Load .env file if present (development)
        // Skip in test environment to avoid interfering with test environment variables
        #[cfg(not(test))]
        {
            dotenv::dotenv().ok(); // Ignore errors (file may not exist)
        }
        
        // Load and validate all fields
        // Note: redis_url must be loaded first for timeout detection
        let redis_url = Self::get_env_or_default("REDIS_URL", "redis://localhost:6379/0")?;
        
        let config = Self {
            bind_address: Self::get_env_or_default("BIND_ADDRESS", "0.0.0.0")?,
            port: Self::parse_port()?,
            redis_url: redis_url.clone(),
            redis_pool_max_size: Self::parse_u32_or_default("REDIS_POOL_MAX_SIZE", 10)?,
            redis_pool_min_idle: Self::parse_u32_or_default("REDIS_POOL_MIN_IDLE", 0)?, // Lazy initialization - set to 0 for production
            redis_pool_max_lifetime_secs: Self::parse_u64_or_default("REDIS_POOL_MAX_LIFETIME_SECS", 1800)?,
            redis_pool_idle_timeout_secs: Self::parse_u64_or_default("REDIS_POOL_IDLE_TIMEOUT_SECS", 300)?,
            redis_connection_timeout_secs: Self::detect_redis_connection_timeout(&redis_url)?,
            redis_operation_timeout_secs: Self::parse_u64_or_default("REDIS_OPERATION_TIMEOUT_SECS", 2)?,
            database_url: Self::get_optional_env("DATABASE_URL")?,
            interceptor_private_key_path: Self::get_required_path("INTERCEPTOR_PRIVATE_KEY_PATH")?,
            policies_yaml_path: Self::get_optional_path("POLICIES_YAML_PATH")?,
            tool_registry_yaml_path: Self::get_required_path("TOOL_REGISTRY_YAML_PATH")?,
            mcp_proxy_timeout_secs: Self::parse_u64_or_default("MCP_PROXY_TIMEOUT_SECS", 5)?,
            request_timeout_secs: Self::parse_u64_or_default("REQUEST_TIMEOUT_SECS", 30)?,
            body_size_limit_bytes: Self::parse_usize_or_default("BODY_SIZE_LIMIT_BYTES", 2 * 1024 * 1024)?,
            rate_limit_per_minute: Self::parse_u32_or_default("RATE_LIMIT_PER_MINUTE", 100)?,
            log_level: Self::get_env_or_default("LOG_LEVEL", "info")?,
            log_format: Self::get_env_or_default("LOG_FORMAT", "json")?,
        };
        
        // Post-load validation
        config.validate()?;
        
        Ok(config)
    }
    
    /// Get environment variable or return default value
    fn get_env_or_default(key: &str, default: &str) -> Result<String, InterceptorError> {
        Ok(env::var(key).unwrap_or_else(|_| default.to_string()))
    }
    
    /// Get optional environment variable
    fn get_optional_env(key: &str) -> Result<Option<String>, InterceptorError> {
        match env::var(key) {
            Ok(value) if !value.is_empty() => Ok(Some(value)),
            _ => Ok(None),
        }
    }
    
    /// Get required file path from environment variable
    fn get_required_path(key: &str) -> Result<PathBuf, InterceptorError> {
        let value = env::var(key)
            .map_err(|_| InterceptorError::ConfigurationError(
                format!("{} not set", key)
            ))?;
        
        if value.is_empty() {
            return Err(InterceptorError::ConfigurationError(
                format!("{} is empty", key)
            ));
        }
        
        Ok(PathBuf::from(value))
    }
    
    /// Get optional file path from environment variable
    fn get_optional_path(key: &str) -> Result<Option<PathBuf>, InterceptorError> {
        match env::var(key) {
            Ok(value) if !value.is_empty() => Ok(Some(PathBuf::from(value))),
            _ => Ok(None),
        }
    }
    
    /// Parse port from PORT environment variable
    fn parse_port() -> Result<u16, InterceptorError> {
        let port_str = env::var("PORT").unwrap_or_else(|_| "8000".to_string());
        let port = port_str.parse::<u16>()
            .map_err(|e| InterceptorError::ConfigurationError(
                format!("Invalid PORT value '{}': {}", port_str, e)
            ))?;
        
        if port == 0 {
            return Err(InterceptorError::ConfigurationError(
                "PORT must be between 1 and 65535".to_string()
            ));
        }
        
        Ok(port)
    }
    
    /// Parse u64 from environment variable or return default
    fn parse_u64_or_default(key: &str, default: u64) -> Result<u64, InterceptorError> {
        match env::var(key) {
            Ok(value) => {
                let parsed = value.parse::<u64>()
                    .map_err(|e| InterceptorError::ConfigurationError(
                        format!("Invalid {} value '{}': {}", key, value, e)
                    ))?;
                
                if parsed == 0 {
                    return Err(InterceptorError::ConfigurationError(
                        format!("{} must be greater than 0", key)
                    ));
                }
                
                Ok(parsed)
            }
            _ => Ok(default),
        }
    }
    
    /// Parse u32 from environment variable or return default
    fn parse_u32_or_default(key: &str, default: u32) -> Result<u32, InterceptorError> {
        match env::var(key) {
            Ok(value) => {
                let parsed = value.parse::<u32>()
                    .map_err(|e| InterceptorError::ConfigurationError(
                        format!("Invalid {} value '{}': {}", key, value, e)
                    ))?;
                
                if parsed == 0 {
                    return Err(InterceptorError::ConfigurationError(
                        format!("{} must be greater than 0", key)
                    ));
                }
                
                Ok(parsed)
            }
            _ => Ok(default),
        }
    }
    
    /// Parse usize from environment variable or return default
    fn parse_usize_or_default(key: &str, default: usize) -> Result<usize, InterceptorError> {
        match env::var(key) {
            Ok(value) => {
                let parsed = value.parse::<usize>()
                    .map_err(|e| InterceptorError::ConfigurationError(
                        format!("Invalid {} value '{}': {}", key, value, e)
                    ))?;
                
                if parsed == 0 {
                    return Err(InterceptorError::ConfigurationError(
                        format!("{} must be greater than 0", key)
                    ));
                }
                
                Ok(parsed)
            }
            _ => Ok(default),
        }
    }
    
    /// Detect Redis connection timeout based on environment
    /// 
    /// Auto-detects WSL/localhost scenarios and uses longer timeouts.
    /// Can be overridden with REDIS_CONNECTION_TIMEOUT_SECS environment variable.
    /// 
    /// - WSL/localhost (127.0.0.1 or localhost): 15 seconds (WSL port forwarding can be very slow on first connection)
    /// - Native Redis: 5 seconds (direct connection, but still allow some buffer)
    fn detect_redis_connection_timeout(redis_url: &str) -> Result<u64, InterceptorError> {
        // Check if explicitly set
        if let Ok(val) = env::var("REDIS_CONNECTION_TIMEOUT_SECS") {
            return Self::parse_u64(&val, "REDIS_CONNECTION_TIMEOUT_SECS");
        }
        
        // Auto-detect: WSL/localhost needs much longer timeout due to port forwarding overhead
        // First connection through WSL port forwarding can take 10-15 seconds
        let is_localhost = redis_url.contains("localhost") || redis_url.contains("127.0.0.1");
        Ok(if is_localhost { 15 } else { 5 })
    }
    
    /// Parse u64 from environment variable (no default)
    fn parse_u64(key: &str, env_key: &str) -> Result<u64, InterceptorError> {
        let parsed = key.parse::<u64>()
            .map_err(|e| InterceptorError::ConfigurationError(
                format!("Invalid {} value '{}': {}", env_key, key, e)
            ))?;
        
        if parsed == 0 {
            return Err(InterceptorError::ConfigurationError(
                format!("{} must be greater than 0", env_key)
            ));
        }
        
        Ok(parsed)
    }
    
    /// Validate all configuration values
    fn validate(&self) -> Result<(), InterceptorError> {
        // Validate port range (u16 max is 65535, so only check for 0)
        if self.port == 0 {
            return Err(InterceptorError::ConfigurationError(
                format!("Invalid PORT value '{}': must be between 1 and 65535", self.port)
            ));
        }
        
        // Validate required file paths
        Self::validate_file_path(&self.interceptor_private_key_path, "Private key file")?;
        Self::validate_file_path(&self.tool_registry_yaml_path, "Tool registry file")?;
        
        // Validate optional file paths
        if let Some(ref path) = self.policies_yaml_path {
            Self::validate_file_path(path, "Policies YAML file")?;
        }
        
        // Validate URLs
        Self::validate_url(&self.redis_url, "Redis URL")?;
        if let Some(ref url) = self.database_url {
            Self::validate_url(url, "Database URL")?;
        }
        
        // Validate mutually exclusive fields
        if self.database_url.is_none() && self.policies_yaml_path.is_none() {
            return Err(InterceptorError::ConfigurationError(
                "Either DATABASE_URL or POLICIES_YAML_PATH must be set".to_string()
            ));
        }
        
        // Validate log level
        Self::validate_log_level(&self.log_level)?;
        
        // Validate log format
        Self::validate_log_format(&self.log_format)?;
        
        Ok(())
    }
    
    /// Validate that a file path exists and is readable
    fn validate_file_path(path: &PathBuf, description: &str) -> Result<(), InterceptorError> {
        if !path.exists() {
            return Err(InterceptorError::ConfigurationError(
                format!("{} not found at {:?}", description, path)
            ));
        }
        
        if !path.is_file() {
            return Err(InterceptorError::ConfigurationError(
                format!("{} is not a file: {:?}", description, path)
            ));
        }
        
        // Check readability (attempt to open)
        std::fs::File::open(path)
            .map_err(|e| InterceptorError::ConfigurationError(
                format!("Cannot read {} at {:?}: {}", description, path, e)
            ))?;
        
        Ok(())
    }
    
    /// Validate URL format
    fn validate_url(url: &str, description: &str) -> Result<(), InterceptorError> {
        url::Url::parse(url)
            .map_err(|e| InterceptorError::ConfigurationError(
                format!("Invalid {} URL '{}': {}", description, url, e)
            ))?;
        Ok(())
    }
    
    /// Validate log level
    fn validate_log_level(level: &str) -> Result<(), InterceptorError> {
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&level.to_lowercase().as_str()) {
            return Err(InterceptorError::ConfigurationError(
                format!("Invalid LOG_LEVEL '{}': must be one of {}", level, valid_levels.join(", "))
            ));
        }
        Ok(())
    }
    
    /// Validate log format
    fn validate_log_format(format: &str) -> Result<(), InterceptorError> {
        if format != "json" && format != "text" {
            return Err(InterceptorError::ConfigurationError(
                format!("Invalid LOG_FORMAT '{}': must be 'json' or 'text'", format)
            ));
        }
        Ok(())
    }
}

impl Config {
    /// Create a test configuration for unit tests
    /// 
    /// This bypasses environment variable loading and file validation
    /// for use in tests that don't need real configuration.
    /// Create a test configuration for unit tests
    /// 
    /// This bypasses environment variable loading and file validation
    /// for use in tests that don't need real configuration.
    pub fn test_config() -> Self {
        use std::path::PathBuf;
        Self {
            bind_address: "0.0.0.0".to_string(),
            port: 8000,
            redis_url: "redis://localhost:6379/0".to_string(),
            redis_pool_max_size: 10,
            redis_pool_min_idle: 0, // Lazy initialization for tests
            redis_pool_max_lifetime_secs: 1800,
            redis_pool_idle_timeout_secs: 300,
            redis_connection_timeout_secs: 15, // Test default (localhost/WSL)
            redis_operation_timeout_secs: 2,
            database_url: Some("postgresql://localhost/test".to_string()),
            interceptor_private_key_path: PathBuf::from("/tmp/test_key.pem"),
            policies_yaml_path: None,
            tool_registry_yaml_path: PathBuf::from("/tmp/test_tools.yaml"),
            mcp_proxy_timeout_secs: 5,
            request_timeout_secs: 30,
            body_size_limit_bytes: 2 * 1024 * 1024,
            rate_limit_per_minute: 100,
            log_level: "info".to_string(),
            log_format: "json".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn setup_test_env() -> TempDir {
        let temp_dir = TempDir::new().unwrap();
        temp_dir
    }

    fn create_test_file(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, "test content").unwrap();
        path
    }

    #[test]
    fn test_get_env_or_default() {
        env::set_var("TEST_VAR", "test_value");
        let result = Config::get_env_or_default("TEST_VAR", "default").unwrap();
        assert_eq!(result, "test_value");
        env::remove_var("TEST_VAR");
    }

    #[test]
    fn test_get_env_or_default_missing() {
        env::remove_var("TEST_VAR_MISSING");
        let result = Config::get_env_or_default("TEST_VAR_MISSING", "default").unwrap();
        assert_eq!(result, "default");
    }

    #[test]
    fn test_parse_port_valid() {
        // Clear PORT first to avoid interference from other tests
        env::remove_var("PORT");
        env::set_var("PORT", "8080");
        let port = Config::parse_port().unwrap();
        assert_eq!(port, 8080);
        env::remove_var("PORT");
    }

    #[test]
    fn test_parse_port_default() {
        env::remove_var("PORT");
        let port = Config::parse_port().unwrap();
        assert_eq!(port, 8000);
    }

    #[test]
    fn test_parse_port_invalid() {
        env::set_var("PORT", "99999");
        let result = Config::parse_port();
        assert!(result.is_err());
        env::remove_var("PORT");
    }

    #[test]
    fn test_validate_log_level() {
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        for level in valid_levels {
            assert!(Config::validate_log_level(level).is_ok());
        }
    }

    #[test]
    fn test_validate_log_level_invalid() {
        assert!(Config::validate_log_level("invalid").is_err());
    }

    #[test]
    fn test_validate_log_format() {
        assert!(Config::validate_log_format("json").is_ok());
        assert!(Config::validate_log_format("text").is_ok());
    }

    #[test]
    fn test_validate_log_format_invalid() {
        assert!(Config::validate_log_format("invalid").is_err());
    }

    #[test]
    fn test_validate_url() {
        assert!(Config::validate_url("redis://localhost:6379/0", "Redis URL").is_ok());
        assert!(Config::validate_url("postgresql://user:pass@localhost/db", "Database URL").is_ok());
    }

    #[test]
    fn test_validate_url_invalid() {
        assert!(Config::validate_url("not-a-url", "Test URL").is_err());
    }

    #[test]
    fn test_validate_file_path() {
        let temp_dir = setup_test_env();
        let test_file = create_test_file(temp_dir.path(), "test.txt");
        
        assert!(Config::validate_file_path(&test_file, "Test file").is_ok());
    }

    #[test]
    fn test_validate_file_path_not_exists() {
        let path = PathBuf::from("/nonexistent/file.txt");
        assert!(Config::validate_file_path(&path, "Test file").is_err());
    }
}
