// Integration tests for configuration management
//
// NOTE: These tests modify environment variables and must run sequentially.
// Run with: cargo test --test integration_mcp_proxy test_config -- --test-threads=1
//
// IMPORTANT: Integration tests are compiled as a separate crate, so dotenv
// may load .env file. We must explicitly set ALL config vars to override any
// values from .env file.

use sentinel_interceptor::config::Config;
use sentinel_interceptor::core::errors::InterceptorError;
use std::env;
use std::fs;
use std::sync::Mutex;
use tempfile::TempDir;

// Global mutex to serialize environment variable access in tests
static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn acquire_env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn setup_test_env() -> TempDir {
    TempDir::new().unwrap()
}

fn create_test_file(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, "test content").unwrap();
    path
}

/// Clear ALL environment variables that Config reads
/// Must be comprehensive to avoid interference from .env file
fn clear_all_env_vars() {
    // CRITICAL: Disable dotenv loading to prevent .env file from overriding test values
    env::set_var("DISABLE_DOTENV", "1");
    
    // Server config
    env::remove_var("BIND_ADDRESS");
    env::remove_var("PORT");
    
    // Redis config
    env::remove_var("REDIS_URL");
    env::remove_var("REDIS_MODE");
    env::remove_var("REDIS_POOL_MAX_SIZE");
    env::remove_var("REDIS_POOL_MIN_IDLE");
    env::remove_var("REDIS_POOL_MAX_LIFETIME_SECS");
    env::remove_var("REDIS_POOL_IDLE_TIMEOUT_SECS");
    env::remove_var("REDIS_CONNECTION_TIMEOUT_SECS");
    env::remove_var("REDIS_OPERATION_TIMEOUT_SECS");
    
    // Database config
    env::remove_var("DATABASE_URL");
    
    // Paths
    env::remove_var("INTERCEPTOR_PRIVATE_KEY_PATH");
    env::remove_var("POLICIES_YAML_PATH");
    env::remove_var("TOOL_REGISTRY_YAML_PATH");
    
    // Timeouts
    env::remove_var("MCP_PROXY_TIMEOUT_SECS");
    env::remove_var("REQUEST_TIMEOUT_SECS");
    env::remove_var("BODY_SIZE_LIMIT_BYTES");
    env::remove_var("RATE_LIMIT_PER_MINUTE");
    
    // Logging
    env::remove_var("LOG_LEVEL");
    env::remove_var("LOG_FORMAT");
}

#[test]
fn test_config_full_load() {
    let _guard = acquire_env_lock();
    clear_all_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    let policies = create_test_file(temp_dir.path(), "policies.yaml");
    
    // Set all environment variables
    env::set_var("BIND_ADDRESS", "127.0.0.1");
    env::set_var("PORT", "9000");
    env::set_var("REDIS_URL", "redis://localhost:6380/1");
    env::set_var("DATABASE_URL", "postgresql://user:pass@localhost/db");
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("POLICIES_YAML_PATH", policies.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("MCP_PROXY_TIMEOUT_SECS", "10");
    env::set_var("REQUEST_TIMEOUT_SECS", "60");
    env::set_var("BODY_SIZE_LIMIT_BYTES", "1048576");
    env::set_var("RATE_LIMIT_PER_MINUTE", "200");
    env::set_var("LOG_LEVEL", "debug");
    env::set_var("LOG_FORMAT", "text");
    
    let config = Config::from_env().unwrap();
    
    // Verify all values loaded correctly
    assert_eq!(config.bind_address, "127.0.0.1");
    assert_eq!(config.port, 9000);
    assert_eq!(config.redis_url, "redis://localhost:6380/1");
    assert_eq!(config.database_url, Some("postgresql://user:pass@localhost/db".to_string()));
    assert_eq!(config.interceptor_private_key_path, key_file);
    assert_eq!(config.policies_yaml_path, Some(policies));
    assert_eq!(config.tool_registry_yaml_path, tool_registry);
    assert_eq!(config.mcp_proxy_timeout_secs, 10);
    assert_eq!(config.request_timeout_secs, 60);
    assert_eq!(config.body_size_limit_bytes, 1048576);
    assert_eq!(config.rate_limit_per_minute, 200);
    assert_eq!(config.log_level, "debug");
    assert_eq!(config.log_format, "text");
    
    clear_all_env_vars();
}

#[test]
fn test_config_minimal_load() {
    let _guard = acquire_env_lock();
    clear_all_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    // Set only required fields (DATABASE_URL satisfies the either/or requirement)
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let config = Config::from_env().unwrap();
    
    // Verify defaults applied
    assert_eq!(config.bind_address, "0.0.0.0");
    assert_eq!(config.port, 8000);
    assert_eq!(config.redis_url, "redis://localhost:6379/0");
    assert_eq!(config.request_timeout_secs, 30);
    assert_eq!(config.body_size_limit_bytes, 2 * 1024 * 1024);
    assert_eq!(config.rate_limit_per_minute, 100);
    assert_eq!(config.log_level, "info");
    assert_eq!(config.log_format, "json");
    
    // Verify required fields set
    assert_eq!(config.interceptor_private_key_path, key_file);
    assert_eq!(config.tool_registry_yaml_path, tool_registry);
    assert_eq!(config.database_url, Some("postgresql://localhost/test".to_string()));
    assert!(config.policies_yaml_path.is_none());
    
    clear_all_env_vars();
}

#[test]
fn test_config_error_missing_required_field() {
    let _guard = acquire_env_lock();
    clear_all_env_vars();
    
    // Don't set any required fields - INTERCEPTOR_PRIVATE_KEY_PATH should fail first
    let result = Config::from_env();
    assert!(result.is_err(), "Should fail when required fields are missing");
    
    if let Err(InterceptorError::ConfigurationError(msg)) = result {
        // The error should mention the missing field
        assert!(
            msg.contains("not set") || msg.contains("INTERCEPTOR_PRIVATE_KEY_PATH"),
            "Error message '{}' should indicate missing required field",
            msg
        );
    } else {
        panic!("Expected ConfigurationError");
    }
    
    clear_all_env_vars();
}

#[test]
fn test_config_error_invalid_file_path() {
    let _guard = acquire_env_lock();
    clear_all_env_vars();
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", "/nonexistent/key.pem");
    env::set_var("TOOL_REGISTRY_YAML_PATH", "/nonexistent/tools.yaml");
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let result = Config::from_env();
    assert!(result.is_err(), "Should fail when file paths don't exist");
    
    if let Err(InterceptorError::ConfigurationError(msg)) = result {
        assert!(
            msg.contains("not found") || msg.contains("file"),
            "Error message '{}' should indicate file not found",
            msg
        );
    }
    
    clear_all_env_vars();
}

#[test]
fn test_config_error_invalid_url() {
    let _guard = acquire_env_lock();
    clear_all_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("REDIS_URL", "not-a-valid-url");
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let result = Config::from_env();
    // Config validates URL format, so should fail
    assert!(result.is_err(), "Should fail on invalid Redis URL");
    
    if let Err(InterceptorError::ConfigurationError(msg)) = result {
        // Accept any URL-related error message
        assert!(
            msg.to_lowercase().contains("url") || msg.contains("redis"),
            "Error message '{}' should indicate URL issue",
            msg
        );
    }
    
    clear_all_env_vars();
}

#[test]
fn test_config_error_mutually_exclusive_fields() {
    let _guard = acquire_env_lock();
    clear_all_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    // Set required file paths but NOT DATABASE_URL or POLICIES_YAML_PATH
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    
    let result = Config::from_env();
    assert!(result.is_err(), "Should fail when neither DATABASE_URL nor POLICIES_YAML_PATH is set");
    
    if let Err(InterceptorError::ConfigurationError(msg)) = result {
        assert!(
            msg.contains("DATABASE_URL") || msg.contains("POLICIES_YAML_PATH"),
            "Error message '{}' should mention the mutually exclusive requirement",
            msg
        );
    }
    
    clear_all_env_vars();
}

#[test]
fn test_config_error_invalid_numeric_value() {
    let _guard = acquire_env_lock();
    clear_all_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("PORT", "invalid");
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let result = Config::from_env();
    assert!(result.is_err(), "Should fail on invalid PORT value");
    
    if let Err(InterceptorError::ConfigurationError(msg)) = result {
        assert!(
            msg.contains("PORT") || msg.contains("Invalid") || msg.contains("invalid"),
            "Error message '{}' should mention PORT or Invalid",
            msg
        );
    }
    
    clear_all_env_vars();
}
