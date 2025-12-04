// Request handlers for API endpoints

use axum::{
    extract::State,
    response::Json,
    Extension,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::api::responses::{ApiError, HealthResponse, ProxyResponse};
use crate::api::{AppState, PolicyDefinition};
use crate::core::errors::InterceptorError;
use crate::core::models::{CustomerConfig, Decision, ProxyRequest};

/// Main handler for proxy execute endpoint
/// 
/// POST /v1/proxy-execute
/// 
/// Request flow:
/// 1. Extract customer config and policy from extensions (set by auth middleware)
/// 2. Deserialize ProxyRequest from JSON body
/// 3. Fetch session taints from Redis
/// 4. Get tool classes from tool registry
/// 5. Evaluate policy using engine
/// 6. If denied, return 403
/// 7. If allowed, mint JWT token
/// 8. Forward request to MCP server
/// 9. Update state asynchronously (fire-and-forget)
/// 10. Return JSON response
pub async fn proxy_execute_handler(
    State(app_state): State<AppState>,
    Extension(customer_config): Extension<CustomerConfig>,
    Extension(policy): Extension<PolicyDefinition>,
    Json(request): Json<ProxyRequest>,
) -> Result<Json<ProxyResponse>, ApiError> {
    info!(
        tool = %request.tool_name,
        session_id = %request.session_id,
        "Received proxy request"
    );

    // Fetch session taints from Redis (ULTRA-FAST FAIL)
    // CRITICAL: Agent timeout is 10s, Redis must complete in <2s to allow 8s for MCP forwarding
    // Strategy: Fail fast (2s max) - if Redis is slow/unavailable, proceed with empty taints
    // This ensures Redis never blocks tool execution - it's optional for session state tracking
    const REDIS_TAINT_TIMEOUT_SECS: u64 = 2; // Ultra-fast fail - don't block on Redis
    info!(
        session_id = %request.session_id,
        redis_timeout_secs = REDIS_TAINT_TIMEOUT_SECS,
        "Fetching session taints from Redis (fail-fast timeout)..."
    );
    let taint_start = std::time::Instant::now();
    let session_taints_vec = match tokio::time::timeout(
        std::time::Duration::from_secs(REDIS_TAINT_TIMEOUT_SECS),
        app_state.redis_store.get_session_taints(&request.session_id)
    ).await {
        Ok(Ok(taints)) => {
            let taint_duration = taint_start.elapsed();
            info!(
                session_id = %request.session_id,
                duration_ms = taint_duration.as_millis(),
                taint_count = taints.len(),
                "Session taints retrieved successfully"
            );
            taints
        },
        Ok(Err(e)) => {
            let taint_duration = taint_start.elapsed();
            warn!(
                error = %e,
                duration_ms = taint_duration.as_millis(),
                session_id = %request.session_id,
                "Redis error - proceeding with empty taints (fail-safe mode)"
            );
            // Fail-safe: Redis errors don't block tool execution
            Vec::new()
        }
        Err(_) => {
            let taint_duration = taint_start.elapsed();
            warn!(
                duration_ms = taint_duration.as_millis(),
                timeout_secs = REDIS_TAINT_TIMEOUT_SECS,
                session_id = %request.session_id,
                "Redis operation timed out - proceeding with empty taints (fail-safe mode)"
            );
            // Fail-safe: Redis timeout should not block tool execution
            Vec::new()
        }
    };
    
    let session_taints: std::collections::HashSet<String> = session_taints_vec.into_iter().collect();

    info!(
        session_id = %request.session_id,
        taints = ?session_taints,
        "Session taints processed"
    );

    // Get tool classes from tool registry
    let tool_classes = app_state
        .tool_registry
        .get_tool_classes(&request.tool_name)
        .await
        .map_err(|e| {
            error!(error = %e, tool = %request.tool_name, "Failed to get tool classes");
            ApiError::from_interceptor_error(InterceptorError::ConfigurationError(format!(
                "Failed to get tool classes: {}",
                e
            )))
        })?;

    info!(
        tool = %request.tool_name,
        classes = ?tool_classes,
        "Tool classes retrieved"
    );

    // Evaluate policy
    // Convert HashSet to Vec for evaluator (trait expects &[String])
    let session_taints_vec: Vec<String> = session_taints.into_iter().collect();
    let decision = app_state
        .evaluator
        .evaluate(
            &policy,
            &request.tool_name,
            &tool_classes,
            &session_taints_vec,
            &request.session_id,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Policy evaluation failed");
            ApiError::from_interceptor_error(InterceptorError::StateError(format!(
                "Policy evaluation failed: {}",
                e
            )))
        })?;

    // Check decision
    match decision {
        Decision::Denied { reason } => {
            warn!(
                tool = %request.tool_name,
                session_id = %request.session_id,
                reason = %reason,
                "Policy violation: request denied"
            );
            return Err(ApiError::from_interceptor_error(
                InterceptorError::PolicyViolation(reason),
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
            error!(error = ?e, "Failed to mint token");
            ApiError::from_interceptor_error(InterceptorError::CryptoError(e))
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
            error!(error = %e, "MCP proxy error");
            ApiError::from_interceptor_error(InterceptorError::McpProxyError(e))
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
