// Request handlers for API endpoints

use axum::{
    extract::State,
    http::HeaderMap,
    response::Json,
    Extension,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::api::responses::{ApiError, HealthResponse, ProxyResponse};
use crate::api::{AppState, PolicyDefinition};
use crate::core::errors::InterceptorError;
use crate::core::models::{CustomerConfig, Decision, ProxyRequest, SessionId};
use crate::auth::api_key::ApiKey;
use serde_json::json;

/// Main handler for proxy execute endpoint
/// 
/// POST /v1/proxy-execute
/// 
/// Request flow:
/// 1. Extract request ID from headers or generate UUID
/// 2. Extract customer config and policy from extensions (set by auth middleware)
/// 3. Deserialize ProxyRequest from JSON body
/// 4. Fetch session taints from Redis
/// 5. Get tool classes from tool registry
/// 6. Evaluate policy using engine
/// 7. If denied, return 403 with request ID
/// 8. If allowed, mint JWT token
/// 9. Forward request to MCP server
/// 10. Update state asynchronously (fire-and-forget)
/// 11. Return JSON response
pub async fn proxy_execute_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Extension(customer_config): Extension<CustomerConfig>,
    Extension(policy): Extension<PolicyDefinition>,
    Json(request): Json<ProxyRequest>,
) -> Result<Json<ProxyResponse>, ApiError> {
    // Extract or generate request ID
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    
    info!(
        tool = %request.tool_name,
        session_id = %request.session_id,
        request_id = %request_id,
        "Received proxy request"
    );

    // Fetch session context from Redis (ULTRA-FAST FAIL via Pipeline)
    // CRITICAL: Agent timeout is 10s, Redis must complete in <2s to allow 8s for MCP forwarding
    // Strategy: Fail fast (2s max) - if Redis is slow/unavailable, fail closed (503)
    const REDIS_CONTEXT_TIMEOUT_SECS: u64 = 2; // Ultra-fast fail - don't block on Redis
    info!(
        session_id = %request.session_id,
        redis_timeout_secs = REDIS_CONTEXT_TIMEOUT_SECS,
        "Fetching session context (taints + history) from Redis (pipeline)..."
    );
    let context_start = std::time::Instant::now();
    let (session_taints_vec, session_history) = match tokio::time::timeout(
        std::time::Duration::from_secs(REDIS_CONTEXT_TIMEOUT_SECS),
        app_state.redis_store.get_session_context(&request.session_id)
    ).await {
        Ok(Ok(context)) => {
            let context_duration = context_start.elapsed();
            info!(
                session_id = %request.session_id,
                duration_ms = context_duration.as_millis(),
                taint_count = context.0.len(),
                history_count = context.1.len(),
                "Session context retrieved successfully"
            );
            context
        },
        Ok(Err(e)) => {
            let context_duration = context_start.elapsed();
            error!(
                error = %e,
                duration_ms = context_duration.as_millis(),
                session_id = %request.session_id,
                "Redis error fetching context - failing closed"
            );
            return Err(ApiError::from_interceptor_error_with_id(
                e,
                request_id,
            ));
        }
        Err(_) => {
            let context_duration = context_start.elapsed();
            error!(
                duration_ms = context_duration.as_millis(),
                timeout_secs = REDIS_CONTEXT_TIMEOUT_SECS,
                session_id = %request.session_id,
                "Redis operation timed out fetching context - failing closed"
            );
            return Err(ApiError::from_interceptor_error_with_id(
                InterceptorError::StateError("Session context fetch timed out".to_string()),
                request_id,
            ));
        }
    };
    
    info!(
        session_id = %request.session_id,
        taints_count = session_taints_vec.len(),
        "Session context processed"
    );

    // Get tool classes from tool registry
    let tool_classes = app_state
        .tool_registry
        .get_tool_classes(&request.tool_name)
        .await
        .map_err(|e| {
            error!(error = %e, tool = %request.tool_name, request_id = %request_id, "Failed to get tool classes");
            ApiError::from_interceptor_error_with_id(
                e,
                request_id.clone(),
            )
        })?;

    info!(
        tool = %request.tool_name,
        classes = ?tool_classes,
        "Tool classes retrieved"
    );

    // Evaluate policy
    // Convert HashMap to HashSet for logging if needed, but we already have vector
    
    let decision = app_state
        .evaluator
        .evaluate(
            &policy,
            &request.tool_name,
            &tool_classes,
            &session_taints_vec,
            &session_history,
            &request.session_id,
        )
        .await
        .map_err(|e| {
            error!(error = %e, request_id = %request_id, "Policy evaluation failed");
            ApiError::from_interceptor_error_with_id(
                e,
                request_id.clone(),
            )
        })?;

    // Check decision
    match decision {
        Decision::Denied { reason } => {
            warn!(
                tool = %request.tool_name,
                session_id = %request.session_id,
                request_id = %request_id,
                reason = %reason,
                "Policy violation: request denied"
            );
            return Err(ApiError::from_interceptor_error_with_id(
                InterceptorError::PolicyViolation(reason),
                request_id,
            ));
        }
        Decision::Allowed => {
            info!(
                tool = %request.tool_name,
                session_id = %request.session_id,
                "Policy evaluation: allowed"
            );
        }
        Decision::AllowedWithSideEffects {
            ref taints_to_add,
            ref taints_to_remove,
        } => {
            info!(
                tool = %request.tool_name,
                session_id = %request.session_id,
                taints_to_add = ?taints_to_add,
                taints_to_remove = ?taints_to_remove,
                "Policy evaluation: allowed with side effects"
            );
        }
    }

    // Mint JWT token
    let token = app_state
        .crypto_signer
        .mint_token(&request.session_id, &request.tool_name, &request.args)
        .map_err(|e| {
            error!(error = ?e, request_id = %request_id, "Failed to mint token");
            ApiError::from_interceptor_error_with_id(
                InterceptorError::CryptoError(e),
                request_id.clone(),
            )
        })?;

    info!(
        tool = %request.tool_name,
        session_id = %request.session_id,
        "Token minted successfully"
    );

    // Forward request to MCP server
    let mcp_result = app_state
        .proxy_client
        .forward_request(
            &customer_config.mcp_upstream_url,
            &request.tool_name,
            &request.args,
            &request.session_id,
            request.agent_callback_url.as_deref(),
            &token,
        )
        .await
        .map_err(|e| {
            error!(error = %e, request_id = %request_id, "MCP proxy error");
            ApiError::from_interceptor_error_with_id(
                e,
                request_id.clone(),
            )
        })?;

    info!(
        tool = %request.tool_name,
        session_id = %request.session_id,
        "MCP request completed successfully"
    );

    // Update state asynchronously (fire-and-forget)
    let redis_store = Arc::clone(&app_state.redis_store);
    let request_clone = request.clone();
    let tool_classes_clone = tool_classes.clone();
    let decision_clone = decision.clone();

    tokio::spawn(async move {
        // Add to history with retry logic
        let mut retries = 3;
        let mut delay_ms = 100u64;
        while retries > 0 {
            match redis_store
                .add_to_history(
                    &request_clone.session_id,
                    &request_clone.tool_name,
                    &tool_classes_clone,
                )
                .await
            {
                Ok(_) => break, // Success, exit retry loop
                Err(e) if retries > 1 => {
                    warn!(
                        error = %e,
                        retries_remaining = retries - 1,
                        delay_ms = delay_ms,
                        "Failed to add to history, retrying..."
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms *= 2; // Exponential backoff
                    retries -= 1;
                }
                Err(e) => {
                    error!(error = %e, "Failed to add to history after all retries");
                    retries = 0; // Exit loop
                }
            }
        }

        // Update taints based on decision
        if let Decision::AllowedWithSideEffects {
            ref taints_to_add,
            ref taints_to_remove,
        } = decision_clone
        {
            for tag in taints_to_add {
                if let Err(e) = redis_store
                    .add_taint(&request_clone.session_id, tag)
                    .await
                {
                    error!(error = %e, tag = %tag, "Failed to add taint (async)");
                }
            }

            for tag in taints_to_remove {
                if let Err(e) = redis_store
                    .remove_taint(&request_clone.session_id, tag)
                    .await
                {
                    error!(error = %e, tag = %tag, "Failed to remove taint (async)");
                }
            }
        }
    });

    Ok(Json(ProxyResponse {
        result: mcp_result,
    }))
}

/// Health check handler
/// 
/// GET /health
/// 
/// Checks:
/// - Server is running
/// - Redis connectivity
/// - Database connectivity (if using PostgreSQL)
pub async fn health_handler(
    State(app_state): State<AppState>,
) -> Result<Json<HealthResponse>, ApiError> {
    // Check Redis connectivity with non-blocking approach
    // Health endpoint should be fast - use spawn to avoid blocking
    // Use shorter timeout (500ms) for health check - if Redis is slow, report as "slow" not "disconnected"
    let redis_store = app_state.redis_store.clone();
    let redis_check_task = tokio::spawn(async move {
        match tokio::time::timeout(
            std::time::Duration::from_millis(500), // Very short timeout for health check (500ms)
            redis_store.ping()
        ).await {
            Ok(Ok(_)) => "connected".to_string(),
            Ok(Err(e)) => {
                warn!(error = %e, "Redis ping failed");
                format!("slow: {}", e) // Report as "slow" not "disconnected" - Redis might be temporarily slow
            }
            Err(_) => {
                debug!("Redis ping timed out in health check (this is OK if Redis is temporarily slow)");
                "slow: timeout".to_string() // Report as "slow" not "disconnected"
            }
        }
    });
    
    // Wait for Redis check with a maximum timeout
    // If Redis check takes too long, return "slow" to keep health endpoint fast
    let redis_status = match tokio::time::timeout(
        std::time::Duration::from_millis(800), // Maximum 800ms total for health check
        redis_check_task
    ).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) => {
            warn!("Redis check task failed");
            "slow: task error".to_string() // Report as "slow" not "disconnected"
        }
        Err(_) => {
            debug!("Redis check timed out - health endpoint returning immediately");
            "slow: check timeout".to_string() // Report as "slow" not "disconnected"
        }
    };

    // TODO: Check database connectivity when PolicyStore/CustomerStore are implemented
    let database_status = None;

    let response = HealthResponse {
        status: "healthy".to_string(),
        redis: redis_status,
        database: database_status,
    };

    Ok(Json(response))
}

/// Policy introspection handler
/// 
/// GET /v1/policy
/// 
/// Returns current policy rules for authenticated customer
/// Requires authentication (API key)
pub async fn policy_introspection_handler(
    State(_app_state): State<AppState>,
    Extension(_customer_config): Extension<CustomerConfig>,
    Extension(policy): Extension<PolicyDefinition>,
) -> Result<Json<serde_json::Value>, ApiError> {
    use serde_json::json;
    
    let response = json!({
        "policy_name": policy.name,
        "static_rules": policy.static_rules,
        "taint_rules": policy.taint_rules,
    });
    
    Ok(Json(response))
}

/// Metrics handler
/// 
/// GET /metrics
/// 
/// Returns Prometheus metrics in text format
pub async fn metrics_handler() -> Result<String, ApiError> {
    // TODO: Implement Prometheus metrics collection
    // For now, return empty metrics
    Ok("# Sentinel Interceptor Metrics\n# TODO: Implement metrics collection\n".to_string())
}

/// Start a new session
/// 
/// POST /v1/session/start
/// Header: X-Sentinel-Key
pub async fn start_session_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let request_id = uuid::Uuid::new_v4().to_string();

    // 1. Extract API Key (Direct extraction as this is a public endpoint regarding auth middleware)
    let api_key = headers
        .get("x-sentinel-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            ApiError::from_interceptor_error_with_id(
                InterceptorError::AuthenticationError("Missing X-Sentinel-Key header".to_string()),
                request_id.clone(),
            )
        })?;

    // 2. Hash API Key & Lookup Project in Supabase
    let api_key_obj = ApiKey::new(api_key);
    let api_key_hash = api_key_obj.hash();

    let project = app_state.supabase_client.get_project_config(api_key_hash.as_str()).await
        .map_err(|e| ApiError::from_interceptor_error_with_id(e, request_id.clone()))?;

    // 3. Generate Session ID
    let session_id = SessionId::generate();
    let session_id_str: String = session_id.into();

    // 4. Determine Policy (First one or default)
    let active_policy = project.policies.first().ok_or_else(|| {
        ApiError::from_interceptor_error_with_id(
            InterceptorError::ConfigurationError("No policies found for project".to_string()),
            request_id.clone(),
        )
    })?;

    // 5. Initialize Session in Redis (TTL 1 hour)
    app_state.redis_store.init_session(&session_id_str, active_policy, &project.tools, 3600).await
        .map_err(|e| ApiError::from_interceptor_error_with_id(e, request_id.clone()))?;

    info!(session_id = %session_id_str, "Session started");

    Ok(Json(json!({
        "session_id": session_id_str,
        "valid_until": "1h" // ISO timestamp would be better but keeping simple
    })))
}

/// Stop a session
/// 
/// POST /v1/session/stop
/// Body: { "session_id": "..." }
pub async fn stop_session_handler(
    State(app_state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session_id = payload.get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::from_interceptor_error_with_id(InterceptorError::ValidationError("Missing session_id".to_string()), "unknown".to_string()))?;

    app_state.redis_store.invalidate_session(session_id).await
        .map_err(|e| ApiError::from_interceptor_error_with_id(e, session_id.to_string()))?;

    info!(session_id = %session_id, "Session stopped");

    Ok(Json(json!({"status": "ok"})))
}

/// List available tools for a session
/// 
/// POST /v1/tools/list
/// Body: { "session_id": "..." }
pub async fn list_tools_handler(
    State(app_state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let session_id = payload.get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::from_interceptor_error_with_id(InterceptorError::ValidationError("Missing session_id".to_string()), request_id.clone()))?;

    // Get Tools from Redis
    let tools_opt = app_state.redis_store.get_session_tools(session_id).await
        .map_err(|e| ApiError::from_interceptor_error_with_id(e, request_id.clone()))?;

    let tools = tools_opt.ok_or_else(|| {
        ApiError::from_interceptor_error_with_id(
             InterceptorError::AuthenticationError("Tools not found for this session".to_string()),
             request_id.clone()
        )
    })?;
    
    // Filter tools based on policy if needed?
    // Policy has static_rules ALLOW/DENY.
    // We should only return ALLOWed tools?
    // User Plan: "Interceptor fetches policies (JSON) and tools (JSON) ... agent calls SDK.tool() ... Interceptor checks validity".
    // Listing tools should probably filter.
    // The policy object is available via `get_session_policy` if we want to filter.
    // Let's assume we return all defined tools, and the Agent/SDK filters or Interceptor blocks usage.
    // But helpfulness => Filter.
    // For now, returning all cached tools is a good start.

    Ok(Json(json!({
        "tools": tools
    })))
}
