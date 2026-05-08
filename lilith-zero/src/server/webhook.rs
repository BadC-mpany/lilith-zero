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
use std::str::FromStr;
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
use super::policy_store::PolicyStore;
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
///
/// `policy_store` is the only mutable part — it holds an `RwLock` internally
/// and can be hot-reloaded via `POST /admin/reload-policies` without restarting
/// the server or touching any other state.
#[derive(Clone)]
pub struct WebhookState {
    /// Runtime configuration (policy path, security level, etc.).
    pub config: Arc<crate::config::Config>,
    /// Optional audit log file path forwarded to [`HookHandler`].
    pub audit_log_path: Option<PathBuf>,
    /// JWT authenticator (no-auth / shared-secret / Entra ID).
    pub auth: Arc<dyn Authenticator>,
    /// Hot-reloadable policy store — Cedar policy sets keyed by agent ID,
    /// plus an optional legacy YAML policy. Atomically swapped on reload.
    pub policy_store: Arc<PolicyStore>,
    /// Bearer token required for admin endpoints. `None` disables admin endpoints.
    pub admin_token: Option<String>,
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the hardened axum [`Router`] with all Copilot Studio webhook routes.
///
/// Layer strategy:
/// - Copilot Studio routes (`/validate`, `/analyze-tool-execution`) use `route_layer`
///   so the 900 ms `TimeoutLayer` + `DefaultBodyLimit` apply only to those routes.
/// - Admin routes (`/admin/*`) are intentionally outside the evaluation timeout:
///   policy reload and upload may take several seconds on Azure Files.
pub fn build_router(state: WebhookState) -> Router {
    Router::new()
        // Copilot Studio routes — gated by evaluation timeout and body limit.
        .route("/", get(handle_validate).post(handle_validate))
        .route("/validate", get(handle_validate).post(handle_validate))
        .route(
            "/analyze-tool-execution",
            post(handle_analyze_tool_execution),
        )
        .route_layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_layer_error))
                .layer(TimeoutLayer::new(Duration::from_millis(
                    EVALUATION_TIMEOUT_MS,
                )))
                .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT_BYTES)),
        )
        // Admin routes — separate X-Admin-Token auth, no evaluation timeout.
        .route("/admin/reload-policies", post(handle_admin_reload))
        .route("/admin/upload-policy", post(handle_admin_upload))
        .route("/admin/status", get(handle_admin_status))
        .with_state(state)
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
    let validation = if !state.policy_store.is_empty().await {
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
    let cedar_policy = state.policy_store.get(agent_id).await;
    let legacy_policy = state.policy_store.get_legacy().await;

    // If policies are configured but this agent_id has no entry, deny (fail-closed).
    if !state.policy_store.is_empty().await && cedar_policy.is_none() && legacy_policy.is_none() {
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
        legacy_policy,
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
    let result = handler.handle_with_reason(hook_input).await;

    // 5. Translate result to Copilot Studio response.
    let response = match result {
        Ok((0, _)) => {
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
        Ok((_, deny_reason)) => {
            let reason =
                deny_reason.unwrap_or_else(|| "blocked by Lilith Zero security policy".to_string());
            if !state.config.lean_logs {
                tracing::warn!(
                    agent_id = %agent_id,
                    conversation_id = %conversation_id,
                    tool = %tool_name,
                    reason = %reason,
                    "Decision: DENY (blocked by policy)"
                );
            }
            let mut resp = AnalyzeToolExecutionResponse::block(reason_codes::STATIC_DENY, reason);
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
// Admin endpoints
// ---------------------------------------------------------------------------

/// Verify the `X-Admin-Token` header against the configured admin token.
///
/// Returns `Ok(())` when the token matches. Returns an HTTP 403 response when
/// the token is wrong, missing, or when no admin token is configured.
#[allow(clippy::result_large_err)]
fn check_admin_token(state: &WebhookState, headers: &HeaderMap) -> Result<(), Response> {
    let configured = match &state.admin_token {
        Some(t) => t,
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "admin endpoints disabled",
                    "detail": "set LILITH_ZERO_ADMIN_TOKEN to enable hot-reload"
                })),
            )
                .into_response());
        }
    };

    let provided = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if provided != configured.as_str() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "invalid admin token"})),
        )
            .into_response());
    }

    Ok(())
}

/// `POST /admin/reload-policies` — atomically reload all policy files from disk.
///
/// Requires `X-Admin-Token` header matching `LILITH_ZERO_ADMIN_TOKEN`.
/// Returns the number of policies reloaded and elapsed milliseconds.
///
/// # Deployment usage
/// ```bash
/// curl -X POST https://your-app.azurewebsites.net/admin/reload-policies \
///      -H "X-Admin-Token: $LILITH_ZERO_ADMIN_TOKEN"
/// ```
async fn handle_admin_reload(State(state): State<WebhookState>, headers: HeaderMap) -> Response {
    if let Err(resp) = check_admin_token(&state, &headers) {
        return resp;
    }

    match state.policy_store.reload().await {
        Ok(stats) => {
            tracing::info!(
                "Admin reload: {} Cedar policy sets reloaded in {}ms",
                stats.cedar_count,
                stats.last_reload_ms
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "reloaded": stats.cedar_count,
                    "elapsed_ms": stats.last_reload_ms,
                    "has_legacy": stats.has_legacy,
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Admin reload failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "reload failed",
                    "detail": e.to_string(),
                })),
            )
                .into_response()
        }
    }
}

/// `POST /admin/upload-policy?agent_id=<uuid>` — upload a Cedar policy file and hot-reload.
///
/// Validates Cedar syntax before writing to disk. On parse failure returns HTTP 400
/// and does not touch the file system or in-memory state (fail-closed).
///
/// # Usage
/// ```bash
/// curl -X POST "https://your-app/admin/upload-policy?agent_id=<UUID>" \
///      -H "X-Admin-Token: $TOKEN" \
///      -H "Content-Type: text/plain" \
///      --data-binary @policy_<UUID>.cedar
/// ```
async fn handle_admin_upload(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = check_admin_token(&state, &headers) {
        return resp;
    }

    let agent_id = match params.get("agent_id") {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "missing required query parameter: agent_id"})),
            )
                .into_response();
        }
    };

    // Validate Cedar syntax before touching disk (fail-closed)
    let content = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "request body must be valid UTF-8"})),
            )
                .into_response();
        }
    };

    if let Err(e) = cedar_policy::PolicySet::from_str(content) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid Cedar policy syntax",
                "detail": e.to_string(),
            })),
        )
            .into_response();
    }

    // Determine write path — use the store's policy_dir, fall back to /home/policies
    let policy_dir = state
        .policy_store
        .policy_dir()
        .cloned()
        .unwrap_or_else(|| std::path::PathBuf::from("/home/policies"));

    if let Err(e) = std::fs::create_dir_all(&policy_dir) {
        tracing::error!(
            "Failed to create policy directory '{}': {e}",
            policy_dir.display()
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to create policy directory", "detail": e.to_string()})),
        )
            .into_response();
    }

    let file_path = policy_dir.join(format!("{agent_id}.cedar"));
    let tmp_path = policy_dir.join(format!(".{agent_id}.cedar.tmp"));
    let body_bytes = body.to_vec();
    let agent_id_log = agent_id.clone();

    // File I/O on a blocking thread to avoid stalling the async runtime.
    // Atomic write: write to a temp file then rename so readers never see a partial file.
    let io_result = tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&policy_dir)?;
        std::fs::write(&tmp_path, &body_bytes)?;
        std::fs::rename(&tmp_path, &file_path)?;
        Ok::<std::path::PathBuf, std::io::Error>(file_path)
    })
    .await;

    let final_path = match io_result {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            tracing::error!("Failed to write policy file for '{}': {e}", agent_id_log);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to write policy file", "detail": e.to_string()})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("spawn_blocking panicked during policy file write: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal error during file write"})),
            )
                .into_response();
        }
    };

    tracing::info!(
        agent_id = %agent_id,
        path = %final_path.display(),
        "Admin upload: policy file written atomically"
    );

    // Reload in-memory state
    match state.policy_store.reload().await {
        Ok(stats) => {
            tracing::info!(
                "Admin upload+reload: {} Cedar policy sets in {}ms",
                stats.cedar_count,
                stats.last_reload_ms
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "uploaded": agent_id,
                    "reloaded": stats.cedar_count,
                    "elapsed_ms": stats.last_reload_ms,
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Reload after upload failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "file written but reload failed",
                    "detail": e.to_string(),
                })),
            )
                .into_response()
        }
    }
}

/// `GET /admin/status` — return current policy store statistics.
///
/// Requires `X-Admin-Token` header matching `LILITH_ZERO_ADMIN_TOKEN`.
async fn handle_admin_status(State(state): State<WebhookState>, headers: HeaderMap) -> Response {
    if let Err(resp) = check_admin_token(&state, &headers) {
        return resp;
    }

    let stats = state.policy_store.stats().await;
    let loaded_secs_ago = stats.loaded_at.elapsed().as_secs();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "cedar_policies": stats.cedar_count,
            "has_legacy_policy": stats.has_legacy,
            "loaded_secs_ago": loaded_secs_ago,
            "last_reload_ms": stats.last_reload_ms,
        })),
    )
        .into_response()
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
// Session TTL & Cleanup
// ---------------------------------------------------------------------------

/// Remove expired session files based on TTL.
///
/// Iterates through session storage directory and deletes `.json` files
/// with modification time older than the given TTL. Logs the count of deleted files.
/// Errors during cleanup are logged but don't fail the function (resilient).
pub fn cleanup_expired_sessions(
    storage_dir: &std::path::Path,
    ttl_secs: u64,
) -> anyhow::Result<usize> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let mut deleted = 0;

    // Silently skip if directory doesn't exist (fresh server)
    if !storage_dir.exists() {
        return Ok(0);
    }

    for entry in std::fs::read_dir(storage_dir)? {
        let path = entry?.path();
        if path.extension() == Some(std::ffi::OsStr::new("json")) {
            match std::fs::metadata(&path) {
                Ok(metadata) => {
                    // Use ok() so a single unreadable mtime doesn't abort the whole loop.
                    if let Some(modified) = metadata
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    {
                        let modified_secs = modified.as_secs();
                        if now.saturating_sub(modified_secs) > ttl_secs {
                            if let Err(e) = std::fs::remove_file(&path) {
                                tracing::warn!(
                                    "Failed to delete expired session {}: {}",
                                    path.display(),
                                    e
                                );
                            } else {
                                tracing::debug!("Cleaned up expired session: {}", path.display());
                                deleted += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to stat session file {}: {}", path.display(), e);
                }
            }
        }
    }

    tracing::info!("Session TTL cleanup: removed {} expired files", deleted);
    Ok(deleted)
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
    tracing::info!(
        "Session storage: {:?} (TTL: {}s)",
        state.config.session_storage_dir,
        state.config.session_ttl_secs,
    );

    let stats = state.policy_store.stats().await;
    if stats.cedar_count == 0 && !stats.has_legacy {
        tracing::warn!(
            "NO POLICIES LOADED - Server will run in fail-closed mode (or AuditOnly if configured)"
        );
    } else {
        tracing::info!(
            "Policies loaded: {} Cedar policy sets{}",
            stats.cedar_count,
            if stats.has_legacy {
                ", 1 legacy YAML"
            } else {
                ""
            },
        );
    }

    if state.admin_token.is_some() {
        tracing::info!("Admin endpoints enabled: POST /admin/reload-policies, GET /admin/status");
    } else {
        tracing::warn!(
            "Admin endpoints disabled (LILITH_ZERO_ADMIN_TOKEN not set). \
             Hot-reload via /admin/reload-policies will return 403."
        );
    }

    if let Err(e) = cleanup_expired_sessions(
        &state.config.session_storage_dir,
        state.config.session_ttl_secs,
    ) {
        tracing::warn!("Session cleanup on startup failed (non-critical): {}", e);
    }

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {bind_addr}: {e}"))?;

    tracing::info!("Webhook server listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
