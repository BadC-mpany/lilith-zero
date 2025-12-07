// Real integration tests for Redis operations

use sentinel_interceptor::api::RedisStore;
use sentinel_interceptor::core::models::HistoryEntry;
use std::sync::Arc;

use super::super::common::*;

#[tokio::test]
async fn test_redis_store_add_and_get_taints() {
    let redis_store = Arc::new(MockRedisStore::default());
    
    // Add taint
    redis_store.add_taint("session-123", "SENSITIVE_DATA").await.unwrap();
    
    // Get taints
    let taints = redis_store.get_session_taints("session-123").await.unwrap();
    assert!(taints.contains(&"SENSITIVE_DATA".to_string()));
}

#[tokio::test]
async fn test_redis_store_add_and_get_history() {
    let redis_store = Arc::new(MockRedisStore::default());
    
    // Add history entry
    redis_store.add_to_history("session-123", "read_file", &["FILE_OPERATION".to_string()]).await.unwrap();
    
    // Get history
    let history = redis_store.get_session_history("session-123").await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].tool, "read_file");
    assert_eq!(history[0].classes, vec!["FILE_OPERATION".to_string()]);
}

#[tokio::test]
async fn test_redis_store_remove_taint() {
    let mut redis_store = MockRedisStore::default();
    redis_store.taints.insert(
        "session-123".to_string(),
        vec!["SENSITIVE_DATA".to_string(), "PII".to_string()],
    );
    let redis_store = Arc::new(redis_store);
    
    // Remove taint
    redis_store.remove_taint("session-123", "SENSITIVE_DATA").await.unwrap();
    
    // Verify removed
    let taints = redis_store.get_session_taints("session-123").await.unwrap();
    assert!(!taints.contains(&"SENSITIVE_DATA".to_string()));
    assert!(taints.contains(&"PII".to_string()));
}

#[tokio::test]
async fn test_redis_store_ping_success() {
    let redis_store = Arc::new(MockRedisStore::default());
    
    let result = redis_store.ping().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_redis_store_ping_failure() {
    let mut redis_store = MockRedisStore::default();
    redis_store.ping_result = Err("Connection failed".to_string());
    let redis_store = Arc::new(redis_store);
    
    let result = redis_store.ping().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_redis_store_get_taints_empty_session() {
    let redis_store = Arc::new(MockRedisStore::default());
    
    let taints = redis_store.get_session_taints("nonexistent-session").await.unwrap();
    assert!(taints.is_empty());
}

#[tokio::test]
async fn test_redis_store_get_history_empty_session() {
    let redis_store = Arc::new(MockRedisStore::default());
    
    let history = redis_store.get_session_history("nonexistent-session").await.unwrap();
    assert!(history.is_empty());
}

#[tokio::test]
async fn test_redis_store_failure_handling() {
    let mut redis_store = MockRedisStore::default();
    redis_store.get_taints_should_fail = true;
    let redis_store = Arc::new(redis_store);
    
    let result = redis_store.get_session_taints("session-123").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Redis connection failed"));
}

#[tokio::test]
async fn test_redis_store_timeout_handling() {
    let mut redis_store = MockRedisStore::default();
    redis_store.get_history_should_timeout = true;
    let redis_store = Arc::new(redis_store);
    
    // Should timeout after 3 seconds (as configured in mock)
    let start = std::time::Instant::now();
    let result = redis_store.get_session_history("session-123").await;
    let duration = start.elapsed();
    
    assert!(result.is_err());
    assert!(duration.as_secs() >= 3);
}

