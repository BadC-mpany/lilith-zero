// Axum web server layer

use axum::{Router, extract::Request};
use std::sync::Arc;

pub mod evaluator_adapter;
pub mod handlers;
pub mod middleware;
pub mod responses;

use crate::core::crypto::CryptoSigner;
use crate::core::models::{CustomerConfig, PolicyDefinition, Decision};

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
    async fn get_session_taints(&self, session_id: &str) -> Result<Vec<String>, String>;
    async fn add_taint(&self, session_id: &str, tag: &str) -> Result<(), String>;
    async fn remove_taint(&self, session_id: &str, tag: &str) -> Result<(), String>;
    async fn add_to_history(&self, session_id: &str, tool: &str, classes: &[String]) -> Result<(), String>;
    async fn get_session_history(&self, session_id: &str) -> Result<Vec<crate::core::models::HistoryEntry>, String>;
    async fn ping(&self) -> Result<(), String>;
}

/// Trait for policy cache operations
/// TODO: Replace with actual PolicyCache implementation
#[async_trait::async_trait]
pub trait PolicyCache: Send + Sync {
    async fn get_policy(&self, policy_name: &str) -> Result<Option<Arc<PolicyDefinition>>, String>;
    async fn put_policy(&self, policy_name: &str, policy: Arc<PolicyDefinition>) -> Result<(), String>;
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
    ) -> Result<Decision, String>;
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
    ) -> Result<serde_json::Value, String>;
}

/// Trait for customer store operations
/// TODO: Replace with actual CustomerStore implementation
#[async_trait::async_trait]
pub trait CustomerStore: Send + Sync {
    async fn lookup_customer(&self, api_key_hash: &str) -> Result<Option<CustomerConfig>, String>;
}

/// Trait for policy store operations
/// TODO: Replace with actual PolicyStore implementation
#[async_trait::async_trait]
pub trait PolicyStore: Send + Sync {
    async fn load_policy(&self, policy_name: &str) -> Result<Option<Arc<PolicyDefinition>>, String>;
}

/// Trait for tool registry operations
/// TODO: Replace with actual ToolRegistry implementation
#[async_trait::async_trait]
pub trait ToolRegistry: Send + Sync {
    async fn get_tool_classes(&self, tool_name: &str) -> Result<Vec<String>, String>;
}

/// Configuration struct
/// TODO: Replace with actual Config implementation
#[derive(Debug, Clone)]
pub struct Config {
    pub request_timeout_secs: u64,
    pub body_size_limit_bytes: usize,
    pub rate_limit_per_minute: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            request_timeout_secs: 30,
            body_size_limit_bytes: 2 * 1024 * 1024, // 2MB
            rate_limit_per_minute: 100,
        }
    }
}

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
    app_state: AppState,
    auth_state: Option<Arc<crate::auth::auth_middleware::AuthState>>,
) -> Router<AppState> {
    use axum::{middleware::Next, extract::State};
    
    let mut router = Router::new()
        .route("/v1/proxy-execute", axum::routing::post(handlers::proxy_execute_handler))
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

    // Middleware layers - TODO: Fix layer error type compatibility with Axum 0.7
    // These layers need to be applied via ServiceBuilder or with proper error type conversion
    // .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
    // .layer(TimeoutLayer::new(std::time::Duration::from_secs(30)))
    // Rate limiting skipped for now - will be added when auth middleware is ready
    
    router.with_state(app_state)
}
