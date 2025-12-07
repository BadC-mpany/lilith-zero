// Axum web server layer

use axum::{Router, extract::Request, error_handling::HandleErrorLayer, http::StatusCode, BoxError};
use std::sync::Arc;
use std::time::Duration;
use tower_http::limit::RequestBodyLimitLayer;
use tower::ServiceBuilder;

pub mod evaluator_adapter;
pub mod handlers;
pub mod middleware;
pub mod responses;

use crate::core::crypto::CryptoSigner;
use crate::core::models::{CustomerConfig, PolicyDefinition, Decision};
use crate::core::errors::InterceptorError;

/// Application state containing all shared dependencies
/// 
/// All components are wrapped in Arc for shared ownership across async tasks.
/// Components must be Send + Sync for thread safety.
/// 
/// Note: AppState itself is wrapped in Arc when used with Axum router.
#[derive(Clone)]
pub struct AppState {
    pub crypto_signer: Arc<CryptoSigner>,
    // TODO: Replace with actual implementations when modules are ready
    pub redis_store: Arc<dyn RedisStore + Send + Sync>,
    pub policy_cache: Arc<dyn PolicyCache + Send + Sync>,
    pub evaluator: Arc<dyn PolicyEvaluator + Send + Sync>,
    pub proxy_client: Arc<dyn ProxyClient + Send + Sync>,
    pub customer_store: Arc<dyn CustomerStore + Send + Sync>,
    pub policy_store: Arc<dyn PolicyStore + Send + Sync>,
    pub tool_registry: Arc<dyn ToolRegistry + Send + Sync>,
    pub config: Arc<Config>,
}

/// Trait for Redis store operations
/// TODO: Replace with actual RedisStore implementation
#[async_trait::async_trait]
pub trait RedisStore: Send + Sync {
    async fn get_session_taints(&self, session_id: &str) -> Result<Vec<String>, InterceptorError>;
    async fn add_taint(&self, session_id: &str, tag: &str) -> Result<(), InterceptorError>;
    async fn remove_taint(&self, session_id: &str, tag: &str) -> Result<(), InterceptorError>;
    async fn add_to_history(&self, session_id: &str, tool: &str, classes: &[String]) -> Result<(), InterceptorError>;
    async fn get_session_history(&self, session_id: &str) -> Result<Vec<crate::core::models::HistoryEntry>, InterceptorError>;
    async fn ping(&self) -> Result<(), InterceptorError>;
}

/// Trait for policy cache operations
/// TODO: Replace with actual PolicyCache implementation
#[async_trait::async_trait]
pub trait PolicyCache: Send + Sync {
    async fn get_policy(&self, policy_name: &str) -> Result<Option<Arc<PolicyDefinition>>, InterceptorError>;
    async fn put_policy(&self, policy_name: &str, policy: Arc<PolicyDefinition>) -> Result<(), InterceptorError>;
}

/// Trait for policy evaluation
/// TODO: Replace with actual PolicyEvaluator implementation
#[async_trait::async_trait]
pub trait PolicyEvaluator: Send + Sync {
    async fn evaluate(
        &self,
        policy: &PolicyDefinition,
        tool_name: &str,
        tool_classes: &[String],
        session_taints: &[String],
        session_id: &str,
    ) -> Result<Decision, InterceptorError>;
}

/// Trait for MCP proxy client
/// TODO: Replace with actual ProxyClient implementation
#[async_trait::async_trait]
pub trait ProxyClient: Send + Sync {
    async fn forward_request(
        &self,
        url: &str,
        tool_name: &str,
        args: &serde_json::Value,
        session_id: &str,
        callback_url: Option<&str>,
        token: &str,
    ) -> Result<serde_json::Value, InterceptorError>;
}

/// Trait for customer store operations
/// TODO: Replace with actual CustomerStore implementation
#[async_trait::async_trait]
pub trait CustomerStore: Send + Sync {
    async fn lookup_customer(&self, api_key_hash: &str) -> Result<Option<CustomerConfig>, InterceptorError>;
}

/// Trait for policy store operations
/// TODO: Replace with actual PolicyStore implementation
#[async_trait::async_trait]
pub trait PolicyStore: Send + Sync {
    async fn load_policy(&self, policy_name: &str) -> Result<Option<Arc<PolicyDefinition>>, InterceptorError>;
}

/// Trait for tool registry operations
/// TODO: Replace with actual ToolRegistry implementation
#[async_trait::async_trait]
pub trait ToolRegistry: Send + Sync {
    async fn get_tool_classes(&self, tool_name: &str) -> Result<Vec<String>, InterceptorError>;
}

/// Configuration struct
// Re-export Config from config module
pub use crate::config::Config;

/// Create the Axum router with all routes and middleware
/// 
/// Middleware stack (outermost to innermost):
/// - Auth middleware - API key extraction and validation (applied to protected routes only)
/// - Tracing middleware (tower-http::trace) - request ID generation, structured logging
/// - Body size limit (tower-http::limit) - 2MB max body size
/// - Request timeout (tower::timeout) - 30s global timeout
/// - Rate limiting (tower_governor) - TODO: will be implemented with auth middleware
/// 
/// Note: Panic recovery is handled automatically by Tower.
/// Note: `/health` and `/metrics` endpoints bypass auth middleware.
pub fn create_router(
    app_state: &AppState,
    auth_state: Option<Arc<crate::auth::auth_middleware::AuthState>>,
) -> Router<AppState> {
    use axum::{middleware::Next, extract::State};
    
    let mut router = Router::new()
        .route("/v1/proxy-execute", axum::routing::post(handlers::proxy_execute_handler))
        .route("/v1/policy", axum::routing::get(handlers::policy_introspection_handler))
        .route("/health", axum::routing::get(handlers::health_handler))
        .route("/metrics", axum::routing::get(handlers::metrics_handler));

    // Apply auth middleware to protected routes only
    if let Some(auth_state) = auth_state {
        router = router.route_layer(axum::middleware::from_fn_with_state(
            auth_state,
            |state: State<Arc<crate::auth::auth_middleware::AuthState>>,
             request: Request,
             next: Next| async move {
                // Skip auth for health and metrics endpoints
                let path = request.uri().path();
                if path == "/health" || path == "/metrics" {
                    return Ok(next.run(request).await);
                }
                
                // Apply auth middleware to all other routes
                crate::auth::auth_middleware::auth_middleware(state, request, next).await
            },
        ));
    }

    // Apply middleware layers (outermost to innermost):
    // 1. Body size limit - prevents DoS via large request bodies
    // 2. Request timeout - prevents resource exhaustion from hanging requests
    // 3. Auth middleware (already applied via route_layer above)
    // 
    // Note: These layers are applied to all routes including health/metrics
    // Order matters: layers are applied in reverse order (last layer wraps innermost)
    let body_limit = app_state.config.body_size_limit_bytes;
    let timeout_secs = app_state.config.request_timeout_secs;
    
    // Apply body size limit layer (works directly with Axum 0.7)
    router = router.layer(RequestBodyLimitLayer::new(body_limit));
    
    // Apply timeout layer with HandleErrorLayer to convert timeout errors to HTTP responses
    // HandleErrorLayer must come BEFORE timeout to catch the timeout error
    let middleware_stack = ServiceBuilder::new()
        // Handle errors (convert Timeout error to HTTP Response)
        .layer(HandleErrorLayer::new(|e: BoxError| async move {
            let status = if e.is::<tower::timeout::error::Elapsed>() {
                StatusCode::REQUEST_TIMEOUT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, e.to_string())
        }))
        // Apply the timeout
        .timeout(Duration::from_secs(timeout_secs))
        .into_inner();
    
    router.layer(middleware_stack)
}
