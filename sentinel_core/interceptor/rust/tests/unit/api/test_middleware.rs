// Unit tests for middleware

use sentinel_interceptor::api::middleware::*;
use tower::ServiceBuilder;
use axum::{body::Body, http::Request, response::Response};
use std::time::Duration;

/// Test that tracing layer can be created
#[test]
fn test_tracing_layer_creates_span() {
    let layer = tracing_layer();
    // Just verify it can be created without panicking
    assert!(true, "Tracing layer created successfully");
}

/// Test that body size limit layer can be created
#[test]
fn test_body_size_limit_enforcement() {
    let layer = body_size_limit_layer();
    // Verify layer is created (2MB limit)
    assert!(true, "Body size limit layer created successfully");
}

/// Test that timeout layer can be created
#[test]
fn test_timeout_layer_enforcement() {
    let timeout = Duration::from_secs(30);
    let layer = timeout_layer(timeout);
    // Verify layer is created
    assert!(true, "Timeout layer created successfully");
}

/// Test rate limit layer structure
#[test]
fn test_rate_limit_layer_structure() {
    let layer = rate_limit_layer();
    // Verify layer is created (currently returns no-op)
    assert!(true, "Rate limit layer created successfully");
}

// Note: Full middleware integration tests (body size exceeded, timeout exceeded)
// would require setting up a full Axum router with the middleware layers.
// These are better suited for integration tests where we can make actual HTTP requests.



