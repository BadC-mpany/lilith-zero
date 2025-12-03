// Load tests for connection pooling

use sentinel_interceptor::api::ProxyClient;
use sentinel_interceptor::proxy::ProxyClientImpl;
use mockito::Server;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task;

async fn create_test_client() -> ProxyClientImpl {
    ProxyClientImpl::new(5).unwrap()
}

#[tokio::test]
async fn test_proxy_client_connection_pooling() {
    let mut server = Server::new_async().await;
    let client = Arc::new(create_test_client().await);
    
    // Create multiple mocks for concurrent requests
    let mut mocks = Vec::new();
    for _ in 0..10 {
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "result": {"status": "success"},
                    "id": "test-id"
                })
                .to_string(),
            )
            .create();
        mocks.push(mock);
    }
    
    // Make 10 concurrent requests using the same client
    let start = Instant::now();
    let mut handles = Vec::new();
    
    for i in 0..10 {
        let client_clone = client.clone();
        let url = server.url();
        let handle = task::spawn(async move {
            client_clone
                .forward_request(
                    &url,
                    "test_tool",
                    &json!({"index": i}),
                    "test_session",
                    None,
                    "test_token",
                )
                .await
        });
        handles.push(handle);
    }
    
    // Wait for all requests to complete
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }
    
    let elapsed = start.elapsed();
    
    // Verify all requests succeeded
    for result in results {
        assert!(result.is_ok());
    }
    
    // Verify all mocks were called
    for mock in mocks {
        mock.assert();
    }
    
    // Connection pooling should make concurrent requests efficient
    // All 10 requests should complete quickly (much faster than sequential)
    println!("10 concurrent requests completed in {:?}", elapsed);
    assert!(elapsed < Duration::from_secs(2), "Concurrent requests should complete quickly with connection pooling");
}

#[tokio::test]
async fn test_proxy_client_sequential_vs_concurrent() {
    let mut server = Server::new_async().await;
    let client = Arc::new(create_test_client().await);
    
    // Create mocks
    let mut mocks = Vec::new();
    for _ in 0..5 {
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "result": {"status": "success"},
                    "id": "test-id"
                })
                .to_string(),
            )
            .create();
        mocks.push(mock);
    }
    
    // Sequential requests
    let start = Instant::now();
    for i in 0..5 {
        let _ = client
            .forward_request(
                &server.url(),
                "test_tool",
                &json!({"index": i}),
                "test_session",
                None,
                "test_token",
            )
            .await
            .unwrap();
    }
    let sequential_time = start.elapsed();
    
    // Reset mocks
    drop(mocks);
    let mut mocks = Vec::new();
    for _ in 0..5 {
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "result": {"status": "success"},
                    "id": "test-id"
                })
                .to_string(),
            )
            .create();
        mocks.push(mock);
    }
    
    // Concurrent requests
    let start = Instant::now();
    let mut handles = Vec::new();
    for i in 0..5 {
        let client_clone = client.clone();
        let url = server.url();
        let handle = task::spawn(async move {
            client_clone
                .forward_request(
                    &url,
                    "test_tool",
                    &json!({"index": i}),
                    "test_session",
                    None,
                    "test_token",
                )
                .await
        });
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await.unwrap().unwrap();
    }
    let concurrent_time = start.elapsed();
    
    // Verify all mocks were called
    for mock in mocks {
        mock.assert();
    }
    
    // Concurrent requests should be faster (or at least not slower)
    println!("Sequential: {:?}, Concurrent: {:?}", sequential_time, concurrent_time);
    // Note: With local mock server, the difference may be minimal, but concurrent should not be slower
    assert!(concurrent_time <= sequential_time * 2, "Concurrent requests should not be significantly slower");
}

#[tokio::test]
async fn test_proxy_client_high_concurrency() {
    let mut server = Server::new_async().await;
    let client = Arc::new(create_test_client().await);
    
    // Create 50 mocks for high concurrency test
    let mut mocks = Vec::new();
    for _ in 0..50 {
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "result": {"status": "success"},
                    "id": "test-id"
                })
                .to_string(),
            )
            .create();
        mocks.push(mock);
    }
    
    // Make 50 concurrent requests
    let start = Instant::now();
    let mut handles = Vec::new();
    
    for i in 0..50 {
        let client_clone = client.clone();
        let url = server.url();
        let handle = task::spawn(async move {
            client_clone
                .forward_request(
                    &url,
                    "test_tool",
                    &json!({"index": i}),
                    "test_session",
                    None,
                    "test_token",
                )
                .await
        });
        handles.push(handle);
    }
    
    // Wait for all requests
    let mut success_count = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            success_count += 1;
        }
    }
    
    let elapsed = start.elapsed();
    
    // Verify all requests succeeded
    assert_eq!(success_count, 50, "All 50 concurrent requests should succeed");
    
    // Verify all mocks were called
    for mock in mocks {
        mock.assert();
    }
    
    // High concurrency should complete in reasonable time
    println!("50 concurrent requests completed in {:?}", elapsed);
    assert!(elapsed < Duration::from_secs(10), "50 concurrent requests should complete within 10 seconds");
}

