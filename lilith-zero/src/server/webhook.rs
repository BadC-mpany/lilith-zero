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
//! - Malformed request bodies → HTTP 400, never allow.
//! - Auth failures → HTTP 401, never allow.
//! - Internal errors → HTTP 500, block implied (fail-closed).
//! - Bodies exceeding [`REQUEST_BODY_LIMIT_BYTES`] → HTTP 413 (no allow).
//! - Evaluations exceeding [`EVALUATION_TIMEOUT_MS`] → HTTP 503 (Copilot Studio
//!   may default to "allow" on timeout — document this limitation explicitly).
//!
//! # `x-ms-correlation-id`
//! The MS spec includes an `x-ms-correlation-id` header for request tracing.
//! We extract it from every incoming request, include it in the tracing span,
//! and echo it back as a response header so Copilot Studio can correlate entries
//! across its logs and ours.
//!
//! # Response-time budget
//! Copilot Studio defaults to "allow" if the webhook doesn't respond within
//! 1 000 ms. We enforce a 900 ms server-side timeout (100 ms margin). If *our*
//! timeout fires, we return 503 and log a warning; Copilot Studio will have
//! already received the response within 900 ms and will default to allow.
//! This is a known limitation of client-side hook architectures — document it
//! in the ITRisk/ITSec section and enforce defence-in-depth at the MCP proxy layer.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    error_handling::HandleErrorLayer,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    BoxError, Json, Router,
};
use tower::timeout::TimeoutLayer;
use tower::ServiceBuilder;

use super::auth::{extract_bearer_token, AuthError, Authenticator};
use super::copilot_studio::{
    error_codes, reason_codes, AnalyzeToolExecutionRequest, AnalyzeToolExecutionResponse,
    ValidationResponse, WebhookErrorResponse,
};
use crate::hook::{HookHandler, HookInput};

// ---------------------------------------------------------------------------
// Hardening constants
// ---------------------------------------------------------------------------

/// Maximum accepted request body size.
///
/// Copilot Studio payloads include conversation history and tool definitions
/// but should never exceed this in practice. Bodies larger than this are
/// rejected with HTTP 413 before reaching any handler.
const REQUEST_BODY_LIMIT_BYTES: usize = 1024 * 1024; // 1 MiB

/// Server-side evaluation timeout (milliseconds).
///
/// Copilot Studio defaults to "allow" if the webhook doesn't respond within
/// 1 000 ms. We use 900 ms to leave a 100 ms network/processing margin.
/// When this fires we return 503; Copilot Studio may allow the action.
///
/// # ITRisk note
/// A 503 from this endpoint means Copilot Studio ALLOWS the tool call.
/// Ensure the MCP proxy layer (lilith-zero run) provides defence-in-depth
/// so a webhook timeout doesn't become a security bypass.
const EVALUATION_TIMEOUT_MS: u64 = 900;

// ---------------------------------------------------------------------------
// Shared server state
// ---------------------------------------------------------------------------

use crate::engine_core::persistence::PersistenceLayer;

/// Immutable state shared across all webhook handler invocations.
#[derive(Clone)]
pub struct WebhookState {
    /// Runtime configuration (policy path, security level, etc.).
    pub config: Arc<crate::config::Config>,
    /// Optional audit log file path forwarded to [`HookHandler`].
    pub audit_log_path: Option<PathBuf>,
    /// JWT authenticator (no-auth / shared-secret / Entra ID).
    pub auth: Arc<dyn Authenticator>,
    /// Policy parsed once at server startup. `None` means no policy configured
    /// (all tool calls will be fail-closed denied by the engine).
    ///
    /// Pre-parsing avoids a blocking disk read + YAML parse on every request,
    /// which would otherwise consume a significant fraction of the 900 ms
    /// evaluation budget and risk triggering the timeout → Copilot Studio allow.
    pub policy: Option<Arc<crate::engine_core::models::PolicyDefinition>>,
    /// Native Cedar policy sets mapped by agent ID.
    pub cedar_policies: std::collections::HashMap<String, Arc<cedar_policy::PolicySet>>,
    /// Persistent session store for taint tracking across HTTP requests.
    /// Sessions are persisted per conversation_id to `{storage_dir}/{conversation_id}.json`.
    /// This allows taints to survive webhook server restarts.
    pub persistence: Arc<PersistenceLayer>,
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the hardened axum [`Router`] with all Copilot Studio webhook routes.
///
/// Layers applied (outermost → innermost):
/// 1. [`HandleErrorLayer`] — converts tower errors (timeout) to JSON responses.
/// 2. [`TimeoutLayer`] — enforces [`EVALUATION_TIMEOUT_MS`] per request.
/// 3. [`DefaultBodyLimit`] — rejects bodies > [`REQUEST_BODY_LIMIT_BYTES`].
pub fn build_router(state: WebhookState) -> Router {
    Router::new()
        .route("/", get(handle_validate).post(handle_validate))
        .route("/validate", get(handle_validate).post(handle_validate))
        .route(
            "/analyze-tool-execution",
            post(handle_analyze_tool_execution),
        )
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_layer_error))
                .layer(TimeoutLayer::new(Duration::from_millis(
                    EVALUATION_TIMEOUT_MS,
                )))
                .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT_BYTES)),
        )
}

/// Convert tower layer errors (timeout, body-limit overflow) into JSON responses.
async fn handle_layer_error(err: BoxError) -> Response {
    if err.is::<tower::timeout::error::Elapsed>() {
        tracing::warn!(
            "Webhook evaluation exceeded {}ms timeout. \
             Copilot Studio may have defaulted to allow.",
            EVALUATION_TIMEOUT_MS
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(WebhookErrorResponse::new(
                error_codes::INTERNAL_ERROR,
                format!(
                    "security evaluation timed out (>{}ms): \
                     Copilot Studio has defaulted to allow for this request",
                    EVALUATION_TIMEOUT_MS
                ),
                503,
            )),
        )
            .into_response();
    }
    tracing::error!("Unhandled layer error: {err}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(WebhookErrorResponse::new(
            error_codes::INTERNAL_ERROR,
            "internal server error",
            500,
        )),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /validate
// ---------------------------------------------------------------------------

/// Health check: validates JWT and confirms the server is properly configured.
///
/// Returns `{"isSuccessful":true,"status":"OK"}` only when auth passes AND a
/// policy file is configured and readable. Returns `isSuccessful:false` with a
/// descriptive status when no policy is loaded — this prevents the operator
/// from believing the server is enforcing policy when it is only running in a
/// fail-closed deny-all state due to missing configuration.
async fn handle_validate(State(state): State<WebhookState>, headers: HeaderMap) -> Response {
    let cid = extract_correlation_id(&headers);

    let resp = do_validate(&state, &headers).await;
    with_correlation_header(resp, cid.as_deref())
}

async fn do_validate(state: &WebhookState, _headers: &HeaderMap) -> Response {
    // We allow /validate without authentication to support the initial
    // registration/save in the Power Platform Admin Center.
    // Real security enforcement happens in /analyze-tool-execution.

    // isSuccessful=true only when a policy was successfully parsed at startup.
    // This is more accurate than checking whether the file path exists: if the
    // policy failed to parse, the file might still be present but the server
    // would be running in fail-closed deny-all mode without enforcing real rules.
    let validation = if state.policy.is_some() || !state.cedar_policies.is_empty() {
        ValidationResponse::ok()
    } else {
        ValidationResponse::not_ready("NO_POLICY_LOADED")
    };

    (StatusCode::OK, Json(validation)).into_response()
}

// ---------------------------------------------------------------------------
// POST /analyze-tool-execution
// ---------------------------------------------------------------------------

/// Tool execution evaluation: parses request, runs policy engine, returns allow/block.
///
/// All error paths are fail-closed: parse errors return HTTP 400, auth failures
/// 401, internal errors 500, engine errors produce `blockAction: true`.
async fn handle_analyze_tool_execution(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let cid = extract_correlation_id(&headers);

    let resp = do_analyze(&state, &headers, body, cid.as_deref()).await;
    with_correlation_header(resp, cid.as_deref())
}

async fn do_analyze(
    state: &WebhookState,
    headers: &HeaderMap,
    body: axum::body::Bytes,
    correlation_id: Option<&str>,
) -> Response {
    if state.config.webhook_debug {
        if let Ok(body_str) = std::str::from_utf8(&body) {
            tracing::info!("RAW_WEBHOOK_PAYLOAD: {}", body_str);
        }
    }

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

    let agent_id = &request.conversation_metadata.agent.id;
    let conversation_id = &request.conversation_metadata.conversation_id;

    if !state.config.lean_logs {
        tracing::info!(
            agent_id = %agent_id,
            conversation_id = %conversation_id,
            correlation_id = correlation_id.unwrap_or("-"),
            tool = %tool_name,
            args = ?hook_input.tool_input,
            "evaluating tool execution request"
        );
    }

    // 4. Evaluate through the security engine.
    let cedar_policy = state.cedar_policies.get(agent_id).cloned();

    // If we have policies loaded but this agent_id isn't found, deny
    if !state.cedar_policies.is_empty() && cedar_policy.is_none() {
        tracing::warn!(agent_id = %agent_id, "Denying request: no policy found for agent");
        return (
            StatusCode::OK,
            Json(AnalyzeToolExecutionResponse::block(
                reason_codes::NO_POLICY,
                format!("No policy loaded for agent_id {}", agent_id),
            )),
        )
            .into_response();
    }

    let mut handler = match HookHandler::with_policy_and_persistence(
        state.config.clone(),
        state.audit_log_path.clone(),
        state.policy.clone(),
        cedar_policy,
        PersistenceLayer::new(state.config.session_storage_dir.clone()),
    ) {
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

    // The HookHandler will handle all persistence (lock, load, save) using
    // the custom persistence layer we passed to it.
    let result = handler.handle(hook_input).await;

    // 5. Translate result to Copilot Studio response.
    let response = match result {
        Ok(0) => {
            if !state.config.lean_logs {
                tracing::info!(
                    agent_id = %agent_id,
                    conversation_id = %conversation_id,
                    tool = %tool_name,
                    "Decision: ALLOW"
                );
            }
            AnalyzeToolExecutionResponse::allow()
        }
        Ok(_) => {
            if !state.config.lean_logs {
                tracing::warn!(
                    agent_id = %agent_id,
                    conversation_id = %conversation_id,
                    tool = %tool_name,
                    "Decision: DENY (blocked by policy)"
                );
            }
            let mut resp = AnalyzeToolExecutionResponse::block(
                reason_codes::STATIC_DENY,
                "blocked by Lilith Zero security policy",
            );
            // Add internal diagnostics for debugging (not shown to end users if configured)
            resp.diagnostics = Some(format!(
                "tool: {}, session: {}, policy: {}",
                tool_name, conversation_id, agent_id
            ));
            resp
        }
        Err(e) => {
            tracing::error!(
                agent_id = %agent_id,
                conversation_id = %conversation_id,
                tool = %tool_name,
                error = %e,
                "Decision: DENY (evaluation error)"
            );
            AnalyzeToolExecutionResponse::block(
                reason_codes::EVAL_ERROR,
                format!("security evaluation failed: {e}"),
            )
        }
    };

    (StatusCode::OK, Json(response)).into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the `x-ms-correlation-id` header value, if present.
fn extract_correlation_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-ms-correlation-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Add `x-ms-correlation-id` response header if a correlation ID was supplied.
///
/// Copilot Studio uses this header to correlate request/response pairs across
/// its own logs and the external security provider's logs.
fn with_correlation_header(mut resp: Response, correlation_id: Option<&str>) -> Response {
    if let Some(cid) = correlation_id {
        if let Ok(val) = HeaderValue::from_str(cid) {
            resp.headers_mut().insert("x-ms-correlation-id", val);
        }
    }
    resp
}

/// Authenticate a request, extracting and validating the Bearer token.
///
/// When the `Authorization` header is absent, the authenticator's
/// `accepts_unauthenticated_requests()` decides: only `NoAuthAuthenticator`
/// returns `true`, making this path explicit and safe against future
/// implementations that might accidentally accept an empty-string token.
async fn authenticate(
    auth: &Arc<dyn Authenticator>,
    auth_header: Option<&str>,
) -> Result<(), AuthError> {
    match extract_bearer_token(auth_header) {
        Ok(token) => auth.validate_token(token).await,
        Err(AuthError::MissingAuthHeader) if auth.accepts_unauthenticated_requests() => Ok(()),
        Err(e) => Err(e),
    }
}

/// Convert an [`AuthError`] to an HTTP 401 JSON response.
fn auth_error_response(e: AuthError) -> Response {
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
pub async fn serve(bind_addr: &str, state: WebhookState) -> anyhow::Result<()> {
    tracing::info!(
        "Lilith Zero webhook server starting on {} (auth: {}, level: {:?}, timeout: {}ms, body_limit: {}KiB)",
        bind_addr,
        state.auth.description(),
        state.config.security_level,
        EVALUATION_TIMEOUT_MS,
        REQUEST_BODY_LIMIT_BYTES / 1024,
    );

    if state.policy.is_none() && state.cedar_policies.is_empty() {
        tracing::warn!(
            "NO POLICIES LOADED - Server will run in fail-closed mode (or AuditOnly if configured)"
        );
    } else {
        tracing::info!(
            "Policies loaded: {} Cedar policy sets, {} legacy policy",
            state.cedar_policies.len(),
            if state.policy.is_some() { "1" } else { "0" }
        );
    }

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {bind_addr}: {e}"))?;

    tracing::info!("Webhook server listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
