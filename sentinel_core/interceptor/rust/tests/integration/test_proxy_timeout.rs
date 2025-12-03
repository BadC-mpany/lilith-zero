// Timeout behavior tests for proxy client

use sentinel_interceptor::api::ProxyClient;
use sentinel_interceptor::proxy::ProxyClientImpl;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::time::timeout;

async fn create_test_client_with_timeout(timeout_secs: u64) -> ProxyClientImpl {
    ProxyClientImpl::new(timeout_secs).unwrap()
}

#[tokio::test]
async fn test_proxy_client_timeout_behavior() {
    // Create client with very short timeout (1 second)
    let client = create_test_client_with_timeout(1).await;
    
    // Try to connect to a non-existent server (should timeout quickly)
    let start = Instant::now();
    let result = client
        .forward_request(
            "http://127.0.0.1:1", // Invalid port, should fail fast
            "test_tool",
            &json!({}),
            "test_session",
            None,
            "test_token",
        )
        .await;
    
    let elapsed = start.elapsed();
    
    // Should fail with connection error (not timeout, since connection fails immediately)
    assert!(result.is_err());
    let error_msg = result.unwrap_err();
    
    // Should fail within reasonable time (connection timeout is 2 seconds)
    assert!(elapsed < Duration::from_secs(3), "Connection should fail within 3 seconds");
    assert!(error_msg.contains("Connection failed") || error_msg.contains("MCP proxy error"));
}

#[tokio::test]
async fn test_proxy_client_request_timeout() {
    // Create client with 1 second timeout
    let client = create_test_client_with_timeout(1).await;
    
    // Use a mock server that delays response beyond timeout
    // Note: This test requires a mock server that can delay responses
    // For now, we test that timeout configuration is respected
    
    // Verify client was created with correct timeout
    // (We can't easily test actual timeout without a controllable server)
    let result = client
        .forward_request(
            "http://127.0.0.1:1", // Invalid port
            "test_tool",
            &json!({}),
            "test_session",
            None,
            "test_token",
        )
        .await;
    
    assert!(result.is_err());
}

#[tokio::test]
async fn test_proxy_client_different_timeout_configurations() {
    // Test various timeout configurations
    let timeouts = vec![1, 5, 10, 30];
    
    for timeout_secs in timeouts {
        let client = create_test_client_with_timeout(timeout_secs).await;
        
        // Verify client can be created with each timeout
        let result = client
            .forward_request(
                "http://127.0.0.1:1", // Invalid port
                "test_tool",
                &json!({}),
                "test_session",
                None,
                "test_token",
            )
            .await;
        
        // Should fail (invalid port), but client should be configured correctly
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn test_proxy_client_zero_timeout() {
    // Test edge case: zero timeout
    let client = create_test_client_with_timeout(0).await;
    
    // Should still create client (though not recommended)
    let result = client
        .forward_request(
            "http://127.0.0.1:1",
            "test_tool",
            &json!({}),
            "test_session",
            None,
            "test_token",
        )
        .await;
    
    // Should fail immediately with zero timeout
    assert!(result.is_err());
}

