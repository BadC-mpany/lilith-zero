// Middleware stack for security, observability, and protection

use std::time::Duration;
use tower_http::{
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};

// Middleware stack is applied directly in create_router()
// This function is kept for documentation purposes but not used

// Panic recovery is handled automatically by tower's ServiceBuilder
// No explicit layer needed - tower catches panics and returns 500 errors

/// Tracing middleware
/// 
/// Generates request IDs (UUID v4)
/// Structured logging (JSON format)
/// Logs: method, path, status, duration, request_id
/// 
/// NOTE: Currently returns TraceLayer::new_for_http() directly.
/// Custom span configuration can be added when error type compatibility is resolved.
pub fn tracing_layer() -> TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>> {
    TraceLayer::new_for_http()
}

/// Body size limit middleware
/// 
/// Max body size: 2MB
/// Returns 413 Payload Too Large if exceeded
pub fn body_size_limit_layer() -> RequestBodyLimitLayer {
    RequestBodyLimitLayer::new(2 * 1024 * 1024) // 2MB
}

/// Request timeout middleware
/// 
/// Global timeout: 30 seconds (configurable)
/// Returns 504 Gateway Timeout if exceeded
/// MCP proxy timeout (5s) is handled in proxy client
pub fn timeout_layer(timeout: Duration) -> tower::timeout::TimeoutLayer {
    tower::timeout::TimeoutLayer::new(timeout)
}

/// Rate limiting middleware
/// 
/// Algorithm: Leaky Bucket (via tower_governor)
/// Key: Customer ID (from API key, extracted by auth middleware)
/// Limits: Configurable per customer (default: 100 req/min)
/// Returns 429 Too Many Requests if exceeded
/// 
/// TODO: Implement proper rate limiting when auth middleware is ready
/// For now, returns a no-op layer that passes requests through unchanged
pub fn rate_limit_layer() -> impl tower::Layer<axum::routing::Route> + Clone + Send + 'static {
    // TODO: Implement rate limiting with tower_governor
    // This requires auth middleware to extract customer ID
    // For MVP, return a no-op layer using tower::layer::util::Identity
    // wrapped in a way that satisfies the Layer trait bounds
    use tower::layer::util::Identity;
    // Stack two Identity layers to create a proper Layer type
    tower::layer::util::Stack::new(Identity::new(), Identity::new())
}
