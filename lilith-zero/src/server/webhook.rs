// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

//! Axum-based webhook server for the Copilot Studio external threat detection API.
//!
//! # Endpoints
//! - `POST /validate` — liveness check (returns `{"isSuccessful":true,"status":"OK"}`).
//! - `POST /analyze-tool-execution` — evaluates a tool call and returns allow/block.
//!
//! # Security invariants
//! - Every request must carry a valid Bearer JWT (configurable auth mode).
//! - Malformed request bodies return HTTP 400 (error response), never allow.
//! - Auth failures return HTTP 401, never allow.
//! - Internal errors return HTTP 500 with `blockAction: true` embedded — the
//!   error path is fail-closed, not fail-open.
//!
//! # Response time
//! The Copilot Studio spec requires a response within 1 000 ms. On timeout,
//! Copilot Studio defaults to "allow". Our latency budget is therefore
//! critical — security evaluation is sub-millisecond; JWT validation (cached
//! after the first call) adds < 5 ms.

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};

use super::auth::{extract_bearer_token, AuthError, Authenticator};
use super::copilot_studio::{
    error_codes, reason_codes, AnalyzeToolExecutionRequest, AnalyzeToolExecutionResponse,
    ValidationResponse, WebhookErrorResponse,
};
use crate::config::Config;
use crate::hook::{HookHandler, HookInput};

// ---------------------------------------------------------------------------
// Shared server state (injected into every handler via axum State extractor)
// ---------------------------------------------------------------------------

/// Immutable state shared across all webhook handler invocations.
#[derive(Clone)]
pub struct WebhookState {
    /// Runtime configuration (policy path, security level, etc.).
    pub config: Arc<Config>,
    /// Optional audit log file path forwarded to [`HookHandler`].
    pub audit_log_path: Option<PathBuf>,
    /// JWT authenticator (no-auth / shared-secret / Entra ID).
    pub auth: Arc<dyn Authenticator>,
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the axum [`Router`] with all Copilot Studio webhook routes.
pub fn build_router(state: WebhookState) -> Router {
    Router::new()
        .route("/validate", post(handle_validate))
        .route(
            "/analyze-tool-execution",
            post(handle_analyze_tool_execution),
        )
        .with_state(state)
}

// ---------------------------------------------------------------------------
// POST /validate
// ---------------------------------------------------------------------------

/// Health check endpoint.
///
/// Validates the JWT (to confirm auth is wired up correctly) and returns a
/// fixed success body. Called by Copilot Studio during initial configuration.
async fn handle_validate(
    State(state): State<WebhookState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());

    // Validate JWT — return 401 on failure.
    if let Err(e) = authenticate(&state.auth, auth_header).await {
        return auth_error_response(e);
    }

    (StatusCode::OK, Json(ValidationResponse::ok())).into_response()
}

// ---------------------------------------------------------------------------
// POST /analyze-tool-execution
// ---------------------------------------------------------------------------

/// Tool execution evaluation endpoint.
///
/// Parses the Copilot Studio request, evaluates it against the policy engine,
/// and returns an allow or block decision. All error paths are fail-closed:
/// parse errors return HTTP 400 (block implied), internal errors return HTTP
/// 500 with `blockAction: true`.
async fn handle_analyze_tool_execution(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // 1. Authenticate.
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());

    if let Err(e) = authenticate(&state.auth, auth_header).await {
        return auth_error_response(e);
    }

    // 2. Parse request body — fail-closed on malformed JSON.
    let request: AnalyzeToolExecutionRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(WebhookErrorResponse::new(
                    error_codes::MISSING_REQUIRED_FIELD,
                    format!("request body parse error: {e}"),
                    400,
                )),
            )
                .into_response();
        }
    };

    // 3. Map to internal HookInput.
    let hook_input: HookInput = super::copilot_studio::to_hook_input(&request);
    let tool_name = hook_input
        .tool_name
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    // 4. Evaluate through the security engine.
    let mut handler = match HookHandler::new(state.config.clone(), state.audit_log_path.clone()) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to create HookHandler: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WebhookErrorResponse::new(
                    error_codes::INTERNAL_ERROR,
                    "internal security engine error",
                    500,
                )),
            )
                .into_response();
        }
    };

    let exit_code = match handler.handle(hook_input).await {
        Ok(code) => code,
        Err(e) => {
            tracing::error!("HookHandler evaluation error for tool '{tool_name}': {e}");
            // Fail-closed: any handler error → block.
            return (
                StatusCode::OK,
                Json(AnalyzeToolExecutionResponse::block(
                    reason_codes::EVAL_ERROR,
                    format!("security evaluation failed: {e}"),
                )),
            )
                .into_response();
        }
    };

    // 5. Translate exit code to Copilot Studio response.
    let response = if exit_code == 0 {
        AnalyzeToolExecutionResponse::allow()
    } else {
        // The exit code is 2 (deny). We pick a generic reason code here;
        // richer reason codes can be added when SecurityDecision carries them.
        AnalyzeToolExecutionResponse::block(
            reason_codes::STATIC_DENY,
            "blocked by Lilith Zero security policy",
        )
    };

    (StatusCode::OK, Json(response)).into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Authenticate a request, extracting and validating the Bearer token.
async fn authenticate(
    auth: &Arc<dyn Authenticator>,
    auth_header: Option<&str>,
) -> Result<(), AuthError> {
    // In no-auth mode the header is optional; other modes require it.
    match extract_bearer_token(auth_header) {
        Ok(token) => auth.validate_token(token).await,
        Err(e @ AuthError::MissingAuthHeader) => {
            // Allow no-auth mode to proceed without a header.
            // For all other modes, missing header is an immediate 401.
            auth.validate_token("").await.map_err(|_| e)
        }
        Err(e) => Err(e),
    }
}

/// Convert an [`AuthError`] to an HTTP 401 response.
fn auth_error_response(e: AuthError) -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(WebhookErrorResponse::new(
            error_codes::JWT_VALIDATION_FAILED,
            e.to_string(),
            401,
        )),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

/// Start the webhook server and block until the listener exits.
///
/// `bind_addr` — e.g. `"0.0.0.0:8080"`.
pub async fn serve(bind_addr: &str, state: WebhookState) -> anyhow::Result<()> {
    tracing::info!(
        "Lilith Zero webhook server starting on {} (auth: {})",
        bind_addr,
        state.auth.description()
    );

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {bind_addr}: {e}"))?;

    tracing::info!("Webhook server listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
