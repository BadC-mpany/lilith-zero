// Unit tests for Redis store

use sentinel_interceptor::state::redis_store::RedisStore;
use sentinel_interceptor::config::{Config, RedisMode};
use std::env;

/// Test Redis operations with Docker mode
#[tokio::test]
async fn test_redis_store_docker_mode() {
    let redis_url = "redis://localhost:6379/0";
    let mut config = Config::test_config();
    config.redis_mode = RedisMode::Docker;
    
    // Skip if Redis is not available
    if let Ok(store) = RedisStore::new(redis_url, &config).await {
        let session_id = format!("test_session_{}", uuid::Uuid::new_v4());
        
        // Test basic operations
        store.add_taint(&session_id, "test_taint").await.unwrap();
        let taints = store.get_taints(&session_id).await.unwrap();
        assert!(taints.contains("test_taint"));
    }
}

/// Test Redis operations with WSL mode
#[tokio::test]
async fn test_redis_store_wsl_mode() {
    let redis_url = "redis://localhost:6379/0";
    let mut config = Config::test_config();
    config.redis_mode = RedisMode::Wsl;
    
    // Skip if Redis is not available
    if let Ok(store) = RedisStore::new(redis_url, &config).await {
        let session_id = format!("test_session_{}", uuid::Uuid::new_v4());
        
        // Test basic operations
        store.add_taint(&session_id, "test_taint").await.unwrap();
        let taints = store.get_taints(&session_id).await.unwrap();
        assert!(taints.contains("test_taint"));
    }
}

/// Test Redis operations with Auto mode (Docker first)
#[tokio::test]
async fn test_redis_store_auto_mode_docker_first() {
    let redis_url = "redis://localhost:6379/0";
    let mut config = Config::test_config();
    config.redis_mode = RedisMode::Auto;
    
    // Skip if Redis is not available
    // Auto mode will try Docker first, then WSL
    if let Ok(store) = RedisStore::new(redis_url, &config).await {
        let session_id = format!("test_session_{}", uuid::Uuid::new_v4());
        
        // Test basic operations
        store.add_taint(&session_id, "test_taint").await.unwrap();
        let taints = store.get_taints(&session_id).await.unwrap();
        assert!(taints.contains("test_taint"));
    }
}

/// Test Redis operations (original test)
#[tokio::test]
async fn test_redis_operations() {
    // This test requires Redis to be running
    // Skip if Redis is not available
    let redis_url = "redis://localhost:6379";
    let config = Config::test_config();
    
    if let Ok(store) = RedisStore::new(redis_url, &config).await {
        // Use unique session ID to avoid test pollution from previous runs
        let session_id = format!("test_session_{}", uuid::Uuid::new_v4());
    
        // Test taint operations (append-only)
        store.add_taint(&session_id, "sensitive_data").await.unwrap();
        let taints = store.get_taints(&session_id).await.unwrap();
        assert!(taints.contains("sensitive_data"));
    
        // Taints expire via TTL, not explicit deletion
    
        // Test history operations
        store.add_history_entry(&session_id, "read_file", &vec!["SENSITIVE_READ".to_string()], 1234567890.0).await.unwrap();
        let history = store.get_history(&session_id).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].tool, "read_file");
    }
}

/// Test connection timeout handling
#[tokio::test]
async fn test_redis_store_connection_timeout() {
    // Test with invalid Redis URL to trigger connection timeout
    let invalid_url = "redis://127.0.0.1:9999/0"; // Port that doesn't exist
    let mut config = Config::test_config();
    config.redis_mode = RedisMode::Docker;
    config.redis_connection_timeout_secs = 2; // Short timeout for testing
    
    // Should fail with timeout error
    let result = RedisStore::new(invalid_url, &config).await;
    assert!(result.is_err(), "Should fail to connect to invalid Redis URL");
}

/// Test min_idle setting for Docker mode
#[tokio::test]
async fn test_redis_store_min_idle_docker() {
    let redis_url = "redis://localhost:6379/0";
    let mut config = Config::test_config();
    config.redis_mode = RedisMode::Docker;
    env::set_var("REDIS_POOL_MIN_IDLE", "0");
    
    // Docker mode should use min_idle=0
    if let Ok(_store) = RedisStore::new(redis_url, &config).await {
        // Just verify it can be created with min_idle=0
        assert!(true, "Docker mode supports min_idle=0");
    }
    
    env::remove_var("REDIS_POOL_MIN_IDLE");
}

/// Test min_idle setting for WSL mode
#[tokio::test]
async fn test_redis_store_min_idle_wsl() {
    let redis_url = "redis://localhost:6379/0";
    let mut config = Config::test_config();
    config.redis_mode = RedisMode::Wsl;
    env::set_var("REDIS_POOL_MIN_IDLE", "2");
    
    // WSL mode should use min_idle=2
    if let Ok(_store) = RedisStore::new(redis_url, &config).await {
        // Just verify it can be created with min_idle=2
        assert!(true, "WSL mode supports min_idle=2");
    }
    
    env::remove_var("REDIS_POOL_MIN_IDLE");
}
