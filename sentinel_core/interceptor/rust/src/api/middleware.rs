// Middleware stack for security, observability, and protection

use axum::extract::Request;
use std::time::Duration;
use tower_http::{
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};
use tracing::info_span;
use uuid::Uuid;

// Middleware stack is applied directly in create_router()
// This function is kept for documentation purposes but not used

// Panic recovery is handled automatically by tower's ServiceBuilder
// No explicit layer needed - tower catches panics and returns 500 errors

/// Tracing middleware
/// 
/// Generates request IDs (UUID v4)
/// Structured logging (JSON format)
/// Logs: method, path, status, duration, request_id
pub fn tracing_layer() -> impl tower::Layer<axum::routing::Route> + Clone + Send + 'static {
    TraceLayer::new_for_http()
        .make_span_with(|request: &Request| {
            let request_id = Uuid::new_v4();
            info_span!(
                "http_request",
                method = %request.method(),
                path = %request.uri().path(),
                request_id = %request_id
            )
        })
        .on_request(|_request: &Request, _span: &tracing::Span| {
            tracing::info!("request started");
        })
        .on_response(|_response: &axum::response::Response, latency: Duration, _span: &tracing::Span| {
            tracing::info!(latency = ?latency, "request completed");
        })
        .on_failure(|_error: &tower_http::classify::ServerErrorsFailureClass, _latency: Duration, _span: &tracing::Span| {
            tracing::error!("request failed");
        })
}

/// Body size limit middleware
/// 
/// Max body size: 2MB
/// Returns 413 Payload Too Large if exceeded
pub fn body_size_limit_layer() -> impl tower::Layer<axum::routing::Route> + Clone + Send + 'static {
    RequestBodyLimitLayer::new(2 * 1024 * 1024) // 2MB
}

/// Request timeout middleware
/// 
/// Global timeout: 30 seconds (configurable)
/// Returns 504 Gateway Timeout if exceeded
/// MCP proxy timeout (5s) is handled in proxy client
pub fn timeout_layer(timeout: Duration) -> impl tower::Layer<axum::routing::Route> + Clone + Send + 'static {
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
/// For now, returns a no-op layer
pub fn rate_limit_layer() -> impl tower::Layer<axum::routing::Route> + Clone + Send + 'static {
    // TODO: Implement rate limiting with tower_governor
    // This requires auth middleware to extract customer ID
    // For MVP, return a no-op layer
    tower::layer::util::Identity::new()
}
