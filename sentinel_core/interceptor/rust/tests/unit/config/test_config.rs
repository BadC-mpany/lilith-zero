// Unit tests for configuration management
// NOTE: These tests must run sequentially to avoid environment variable conflicts

use sentinel_interceptor::config::Config;
use sentinel_interceptor::core::errors::InterceptorError;
use std::env;
use std::fs;
use std::sync::Mutex;
use tempfile::TempDir;

// Global mutex to serialize environment variable access in tests
static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn setup_test_env() -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    temp_dir
}

fn create_test_file(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, "test content").unwrap();
    path
}

fn clear_env_vars() {
    env::remove_var("BIND_ADDRESS");
    env::remove_var("PORT");
    env::remove_var("REDIS_URL");
    env::remove_var("DATABASE_URL");
    env::remove_var("INTERCEPTOR_PRIVATE_KEY_PATH");
    env::remove_var("POLICIES_YAML_PATH");
    env::remove_var("TOOL_REGISTRY_YAML_PATH");
    env::remove_var("MCP_PROXY_TIMEOUT_SECS");
    env::remove_var("REQUEST_TIMEOUT_SECS");
    env::remove_var("BODY_SIZE_LIMIT_BYTES");
    env::remove_var("RATE_LIMIT_PER_MINUTE");
    env::remove_var("LOG_LEVEL");
    env::remove_var("LOG_FORMAT");
}

#[test]
fn test_config_default_values() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    // This will fail because required fields are missing, but we can test defaults
    // by setting required fields
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let config = Config::from_env().unwrap();
    
    // Test defaults
    assert_eq!(config.bind_address, "0.0.0.0");
    assert_eq!(config.port, 8000);
    assert_eq!(config.redis_url, "redis://localhost:6379/0");
    assert_eq!(config.mcp_proxy_timeout_secs, 5);
    assert_eq!(config.request_timeout_secs, 30);
    assert_eq!(config.body_size_limit_bytes, 2 * 1024 * 1024);
    assert_eq!(config.rate_limit_per_minute, 100);
    assert_eq!(config.log_level, "info");
    assert_eq!(config.log_format, "json");
    
    clear_env_vars();
}

#[test]
fn test_config_required_fields_missing() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    // Missing INTERCEPTOR_PRIVATE_KEY_PATH
    let result = Config::from_env();
    assert!(result.is_err());
    if let Err(InterceptorError::ConfigurationError(msg)) = result {
        assert!(msg.contains("INTERCEPTOR_PRIVATE_KEY_PATH"));
    }
}

#[test]
fn test_config_required_paths() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let config = Config::from_env().unwrap();
    assert_eq!(config.interceptor_private_key_path, key_file);
    assert_eq!(config.tool_registry_yaml_path, tool_registry);
    
    clear_env_vars();
}

#[test]
fn test_config_file_path_validation_not_exists() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", "/nonexistent/key.pem");
    env::set_var("TOOL_REGISTRY_YAML_PATH", "/nonexistent/tools.yaml");
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let result = Config::from_env();
    assert!(result.is_err());
    if let Err(InterceptorError::ConfigurationError(msg)) = result {
        assert!(msg.contains("not found") || msg.contains("Private key file") || msg.contains("Tool registry file"));
    }
    
    clear_env_vars();
}

#[test]
fn test_config_url_validation() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("REDIS_URL", "invalid-url");
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let result = Config::from_env();
    assert!(result.is_err());
    if let Err(InterceptorError::ConfigurationError(msg)) = result {
        assert!(msg.contains("Invalid Redis URL"));
    }
    
    clear_env_vars();
}

#[test]
fn test_config_port_validation() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("PORT", "99999"); // Invalid port
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let result = Config::from_env();
    assert!(result.is_err());
    
    clear_env_vars();
}

#[test]
fn test_config_mutually_exclusive_fields() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    // Neither DATABASE_URL nor POLICIES_YAML_PATH set
    
    let result = Config::from_env();
    assert!(result.is_err());
    if let Err(InterceptorError::ConfigurationError(msg)) = result {
        assert!(msg.contains("Either DATABASE_URL or POLICIES_YAML_PATH"));
    }
    
    clear_env_vars();
}

#[test]
fn test_config_mutually_exclusive_fields_database() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let config = Config::from_env().unwrap();
    assert_eq!(config.database_url, Some("postgresql://localhost/test".to_string()));
    
    clear_env_vars();
}

#[test]
fn test_config_mutually_exclusive_fields_yaml() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    let policies = create_test_file(temp_dir.path(), "policies.yaml");
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("POLICIES_YAML_PATH", policies.to_str().unwrap());
    
    let config = Config::from_env().unwrap();
    assert!(config.policies_yaml_path.is_some());
    assert_eq!(config.policies_yaml_path.unwrap(), policies);
    
    clear_env_vars();
}

#[test]
fn test_config_log_level_validation() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("LOG_LEVEL", "invalid");
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let result = Config::from_env();
    assert!(result.is_err());
    if let Err(InterceptorError::ConfigurationError(msg)) = result {
        assert!(msg.contains("Invalid LOG_LEVEL"));
    }
    
    clear_env_vars();
}

#[test]
fn test_config_log_format_validation() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("LOG_FORMAT", "invalid");
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let result = Config::from_env();
    assert!(result.is_err());
    if let Err(InterceptorError::ConfigurationError(msg)) = result {
        assert!(msg.contains("LOG_FORMAT") || msg.contains("json") || msg.contains("text"));
    }
    
    clear_env_vars();
}

#[test]
fn test_config_timeout_validation() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("MCP_PROXY_TIMEOUT_SECS", "0"); // Invalid (must be > 0)
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let result = Config::from_env();
    assert!(result.is_err());
    if let Err(InterceptorError::ConfigurationError(msg)) = result {
        assert!(msg.contains("must be greater than 0") || msg.contains("MCP_PROXY_TIMEOUT_SECS"));
    }
    
    clear_env_vars();
}

#[test]
fn test_config_custom_values() {
    let _guard = ENV_MUTEX.lock().unwrap();
    clear_env_vars();
    
    let temp_dir = setup_test_env();
    let key_file = create_test_file(temp_dir.path(), "key.pem");
    let tool_registry = create_test_file(temp_dir.path(), "tools.yaml");
    
    env::set_var("BIND_ADDRESS", "127.0.0.1");
    env::set_var("PORT", "9000");
    env::set_var("REDIS_URL", "redis://localhost:6380/1");
    env::set_var("INTERCEPTOR_PRIVATE_KEY_PATH", key_file.to_str().unwrap());
    env::set_var("TOOL_REGISTRY_YAML_PATH", tool_registry.to_str().unwrap());
    env::set_var("MCP_PROXY_TIMEOUT_SECS", "10");
    env::set_var("REQUEST_TIMEOUT_SECS", "60");
    env::set_var("BODY_SIZE_LIMIT_BYTES", "1048576");
    env::set_var("RATE_LIMIT_PER_MINUTE", "200");
    env::set_var("LOG_LEVEL", "debug");
    env::set_var("LOG_FORMAT", "text");
    env::set_var("DATABASE_URL", "postgresql://localhost/test");
    
    let config = Config::from_env().unwrap();
    
    assert_eq!(config.bind_address, "127.0.0.1");
    assert_eq!(config.port, 9000);
    assert_eq!(config.redis_url, "redis://localhost:6380/1");
    assert_eq!(config.mcp_proxy_timeout_secs, 10);
    assert_eq!(config.request_timeout_secs, 60);
    assert_eq!(config.body_size_limit_bytes, 1048576);
    assert_eq!(config.rate_limit_per_minute, 200);
    assert_eq!(config.log_level, "debug");
    assert_eq!(config.log_format, "text");
    
    clear_env_vars();
}

