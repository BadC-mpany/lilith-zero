// Request handlers for API endpoints

use axum::{
    extract::State,
    response::Json,
    Extension,
};
use std::sync::Arc;
use tracing::{error, info, warn};

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

    // Fetch session taints from Redis (with timeout to prevent hanging)
    // Convert Vec<String> from trait to HashSet<String> for policy evaluation
    // Use config timeout: connection timeout + operation timeout + buffer
    let redis_timeout = app_state.config.redis_connection_timeout_secs + app_state.config.redis_operation_timeout_secs + 1;
    let session_taints_vec = match tokio::time::timeout(
        std::time::Duration::from_secs(redis_timeout),
        app_state.redis_store.get_session_taints(&request.session_id)
    ).await {
        Ok(Ok(taints)) => taints,
        Ok(Err(e)) => {
            error!(error = %e, "Failed to fetch session taints");
            return Err(ApiError::from_interceptor_error(InterceptorError::StateError(format!(
                "Failed to fetch session state: {}",
                e
            ))));
        }
        Err(_) => {
            error!("Redis operation timed out while fetching session taints");
            // Return empty set on timeout (fail-safe: allow request to proceed)
            warn!("Continuing with empty taint set due to Redis timeout");
            Vec::new()
        }
    };
    
    let session_taints: std::collections::HashSet<String> = session_taints_vec.into_iter().collect();

    info!(
        session_id = %request.session_id,
        taints = ?session_taints,
        "Session taints retrieved"
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
        // Add to history
        if let Err(e) = redis_store
            .add_to_history(
                &request_clone.session_id,
                &request_clone.tool_name,
                &tool_classes_clone,
            )
            .await
        {
            error!(error = %e, "Failed to add to history (async)");
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
    // bb8-redis pool handles reconnection automatically, so no panic recovery needed
    let redis_store = app_state.redis_store.clone();
    let redis_check_task = tokio::spawn(async move {
        match tokio::time::timeout(
            std::time::Duration::from_secs(1), // Shorter timeout for health check (1s instead of 3s)
            redis_store.ping()
        ).await {
            Ok(Ok(_)) => "connected".to_string(),
            Ok(Err(e)) => {
                warn!(error = %e, "Redis ping failed");
                format!("disconnected: {}", e)
            }
            Err(_) => {
                warn!("Redis ping timed out");
                "disconnected: timeout".to_string()
            }
        }
    });
    
    // Wait for Redis check with a maximum timeout
    // If Redis check takes too long, return "checking..." to keep health endpoint fast
    let redis_status = match tokio::time::timeout(
        std::time::Duration::from_secs(2), // Maximum 2 seconds total for health check
        redis_check_task
    ).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) => {
            warn!("Redis check task failed");
            "disconnected: task error".to_string()
        }
        Err(_) => {
            warn!("Redis check timed out - health endpoint returning immediately");
            "checking...".to_string() // Return immediately if Redis check is slow
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
