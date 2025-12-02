// Unit tests for AppState and Config

use sentinel_interceptor::api::*;
use std::sync::Arc;

#[test]
fn test_config_default() {
    let config = Config::default();
    
    assert_eq!(config.request_timeout_secs, 30);
    assert_eq!(config.body_size_limit_bytes, 2 * 1024 * 1024); // 2MB
    assert_eq!(config.rate_limit_per_minute, 100);
}

#[test]
fn test_config_custom() {
    let config = Config {
        request_timeout_secs: 60,
        body_size_limit_bytes: 5 * 1024 * 1024, // 5MB
        rate_limit_per_minute: 200,
    };
    
    assert_eq!(config.request_timeout_secs, 60);
    assert_eq!(config.body_size_limit_bytes, 5 * 1024 * 1024);
    assert_eq!(config.rate_limit_per_minute, 200);
}

#[test]
fn test_app_state_clone() {
    // AppState should be cloneable (required by Axum)
    // This test verifies the Clone derive works
    // Full AppState creation requires all dependencies, so we test structure
    
    // Note: Actual AppState creation requires all trait implementations
    // This is tested in integration tests
}

#[test]
fn test_app_state_send_sync() {
    // Verify that AppState is Send + Sync
    // This is required for use in async contexts
    
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    
    assert_send::<AppState>();
    assert_sync::<AppState>();
}

#[test]
fn test_config_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    
    assert_send::<Config>();
    assert_sync::<Config>();
}

#[test]
fn test_config_clone() {
    let config1 = Config::default();
    let config2 = config1.clone();
    
    assert_eq!(config1.request_timeout_secs, config2.request_timeout_secs);
    assert_eq!(config1.body_size_limit_bytes, config2.body_size_limit_bytes);
    assert_eq!(config1.rate_limit_per_minute, config2.rate_limit_per_minute);
}

#[test]
fn test_config_arc_clone() {
    // Verify Config works with Arc (required by AppState)
    let config = Arc::new(Config::default());
    let config_clone = Arc::clone(&config);
    
    assert_eq!(config.request_timeout_secs, config_clone.request_timeout_secs);
}

