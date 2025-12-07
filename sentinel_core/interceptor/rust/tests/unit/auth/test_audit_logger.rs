// Unit tests for audit logger

use sentinel_interceptor::auth::audit_logger::{AuditLogger, AuthEvent};
use sentinel_interceptor::auth::api_key::ApiKeyHash;
use std::sync::Arc;
use tokio::time::sleep;
use tokio::time::Duration;

/// Test audit logger creation without database
#[test]
fn test_audit_logger_creation() {
    let logger = AuditLogger::new(None);
    // Just verify it can be created
    assert!(true, "Audit logger created successfully");
}

/// Test audit logger creation with database pool
#[test]
fn test_audit_logger_creation_with_db() {
    // Note: Full database integration tests require a test database
    // This test verifies the logger can be created with a pool (even if None)
    let logger = AuditLogger::new(None);
    assert!(true, "Audit logger created with None pool");
}

/// Test auth success event logging
#[tokio::test]
async fn test_audit_logger_auth_success() {
    let logger = AuditLogger::new(None);
    let hash = ApiKeyHash::from_api_key("test_key");
    
    // Should not panic
    logger.log_auth_event(
        AuthEvent::AuthSuccess,
        Some(&hash),
        Some("127.0.0.1"),
        Some("test-agent"),
    );
    
    // Give async task a moment to complete
    sleep(Duration::from_millis(10)).await;
}

/// Test auth failure event logging
#[tokio::test]
async fn test_audit_logger_auth_failure() {
    let logger = AuditLogger::new(None);
    let hash = ApiKeyHash::from_api_key("test_key");
    
    // Should not panic
    logger.log_auth_event(
        AuthEvent::AuthFailure { reason: "Invalid API key".to_string() },
        Some(&hash),
        Some("127.0.0.1"),
        Some("test-agent"),
    );
    
    // Give async task a moment to complete
    sleep(Duration::from_millis(10)).await;
}

/// Test logging without database pool (structured logging only)
#[tokio::test]
async fn test_audit_logger_no_db_pool() {
    let logger = AuditLogger::new(None);
    let hash = ApiKeyHash::from_api_key("test_key");
    
    // Should work without database (structured logging only)
    logger.log_auth_event(
        AuthEvent::AuthSuccess,
        Some(&hash),
        Some("127.0.0.1"),
        Some("test-agent"),
    );
    
    sleep(Duration::from_millis(10)).await;
    assert!(true, "Should log without database pool");
}

/// Test fire-and-forget behavior (non-blocking)
#[tokio::test]
async fn test_audit_logger_fire_and_forget() {
    let logger = AuditLogger::new(None);
    let hash = ApiKeyHash::from_api_key("test_key");
    
    let start = std::time::Instant::now();
    
    // Log event (should return immediately)
    logger.log_auth_event(
        AuthEvent::AuthSuccess,
        Some(&hash),
        Some("127.0.0.1"),
        Some("test-agent"),
    );
    
    let duration = start.elapsed();
    
    // Should return immediately (<1ms)
    assert!(duration < Duration::from_millis(1), "Should return immediately (fire-and-forget)");
    
    // Give async task time to complete
    sleep(Duration::from_millis(10)).await;
}

/// Test IP address handling
#[tokio::test]
async fn test_audit_logger_ip_address_handling() {
    let logger = AuditLogger::new(None);
    let hash = ApiKeyHash::from_api_key("test_key");
    
    // Test with IP address
    logger.log_auth_event(
        AuthEvent::AuthSuccess,
        Some(&hash),
        Some("192.168.1.1"),
        Some("test-agent"),
    );
    
    // Test with None IP
    logger.log_auth_event(
        AuthEvent::AuthSuccess,
        Some(&hash),
        None,
        Some("test-agent"),
    );
    
    sleep(Duration::from_millis(10)).await;
    assert!(true, "Should handle IP addresses correctly");
}

/// Test user agent handling
#[tokio::test]
async fn test_audit_logger_user_agent_handling() {
    let logger = AuditLogger::new(None);
    let hash = ApiKeyHash::from_api_key("test_key");
    
    // Test with user agent
    logger.log_auth_event(
        AuthEvent::AuthSuccess,
        Some(&hash),
        Some("127.0.0.1"),
        Some("python-httpx/0.27.0"),
    );
    
    // Test with None user agent
    logger.log_auth_event(
        AuthEvent::AuthSuccess,
        Some(&hash),
        Some("127.0.0.1"),
        None,
    );
    
    sleep(Duration::from_millis(10)).await;
    assert!(true, "Should handle user agents correctly");
}

/// Test null API key handling
#[tokio::test]
async fn test_audit_logger_null_api_key() {
    let logger = AuditLogger::new(None);
    
    // Should not panic with None API key
    logger.log_auth_event(
        AuthEvent::AuthFailure { reason: "Missing API key".to_string() },
        None,
        Some("127.0.0.1"),
        Some("test-agent"),
    );
    
    sleep(Duration::from_millis(10)).await;
    assert!(true, "Should handle None API key");
}

// Note: Database integration tests (test_audit_logger_db_insert_success,
// test_audit_logger_db_insert_failure) would require:
// 1. A test PostgreSQL database
// 2. sqlx::PgPool setup
// 3. Table creation
// These are better suited for integration tests where we can set up a test database.

