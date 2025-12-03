// Unit tests for proxy client

use sentinel_interceptor::proxy::ProxyClientImpl;

#[test]
fn test_proxy_client_creation() {
    let client = ProxyClientImpl::new(5);
    assert!(client.is_ok());
}

#[test]
fn test_proxy_client_custom_timeout() {
    let client = ProxyClientImpl::new(10);
    assert!(client.is_ok());
}

#[test]
fn test_proxy_client_zero_timeout() {
    // Should still work, though not recommended
    let client = ProxyClientImpl::new(0);
    assert!(client.is_ok());
}

// Note: Error mapping and response parsing tests are covered in integration tests
// since those functions are private helpers. The unit tests here focus on
// client creation and configuration.
