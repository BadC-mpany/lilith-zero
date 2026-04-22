//! Integration tests for the Copilot Studio webhook server.
//!
//! These tests start a real axum server on a random port, send HTTP requests
//! with `reqwest`, and assert on JSON responses.
//!
//! # Test strategy
//! Most integration tests use `NoAuthAuthenticator` so they can focus on
//! routing, payload parsing, and policy evaluation without needing to generate
//! signed JWTs (which has a crypto-provider bootstrapping cost). Auth-specific
//! behaviour (token rejection paths) is tested using `SharedSecretAuthenticator`
//! with pre-fabricated invalid/missing tokens — the server's validation logic,
//! not client-side signing, is what we verify. Auth acceptance (valid token
//! accepted by `SharedSecretAuthenticator`) is covered by the unit tests in
//! `src/server/auth.rs`.
//!
//! # Security invariants checked
//! - Auth failure → HTTP 401, tool call never allowed.
//! - Malformed body → HTTP 400, never allow.
//! - Internal error → HTTP 500, block implied.
//! - No policy → HTTP 200, blockAction=true (fail-closed).
//! - Known-deny tool → blockAction=true.
//! - Known-allow tool → blockAction=false.
//! - Taint state persists across requests with same conversationId.
//! - Different conversationIds have isolated sessions.
//! - Concurrent requests with same conversationId don't corrupt state.
//!
//! # Test naming convention
//! `test_webhook_{endpoint}_{scenario}_{expected_outcome}`

#![cfg(feature = "webhook")]
#![cfg(not(miri))]

use std::io::Write;
use std::sync::Arc;

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde_json::{json, Value};
use tempfile::NamedTempFile;
use tokio::net::TcpListener;

use lilith_zero::config::Config;
use lilith_zero::server::auth::{NoAuthAuthenticator, SharedSecretAuthenticator};
use lilith_zero::server::webhook::{build_router, WebhookState};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a policy YAML to a named temp file. Caller must keep the handle alive.
fn write_temp_policy(yaml: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("temp policy file");
    f.write_all(yaml.as_bytes()).expect("write policy");
    f
}

/// Default test policy: `allowed_tool` → ALLOW, `forbidden_tool` → DENY.
fn default_policy_yaml() -> &'static str {
    r#"
id: webhook-test-policy
customer_id: test
name: Webhook Test Policy
version: 1
static_rules:
  allowed_tool: ALLOW
  forbidden_tool: DENY
taint_rules: []
resource_rules: []
"#
}

/// Spin up a test server on a random OS-assigned port.  Returns the base URL.
async fn start_test_server(state: WebhookState) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind test server");
    let addr = listener.local_addr().expect("get bound addr");
    let app = build_router(state);
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test server crashed");
    });
    format!("http://127.0.0.1:{}", addr.port())
}

/// Build a `WebhookState` with `NoAuthAuthenticator` — use for all tests
/// that focus on routing, payload, and policy (not auth itself).
fn test_state_no_auth(policy_path: &std::path::Path) -> WebhookState {
    let config = Config {
        policies_yaml_path: Some(policy_path.to_path_buf()),
        ..Config::default()
    };
    WebhookState {
        config: Arc::new(config),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
    }
}

/// Build a `WebhookState` with `SharedSecretAuthenticator` — use for auth
/// rejection tests only (we never need to generate a valid token client-side).
fn test_state_with_shared_secret_auth(policy_path: &std::path::Path) -> WebhookState {
    let config = Config {
        policies_yaml_path: Some(policy_path.to_path_buf()),
        ..Config::default()
    };
    WebhookState {
        config: Arc::new(config),
        audit_log_path: None,
        auth: Arc::new(SharedSecretAuthenticator::new("test-webhook-secret", None)),
    }
}

/// Build an `analyze-tool-execution` request body JSON.
fn analyze_request(conversation_id: &str, tool_name: &str, input_values: Value) -> Value {
    json!({
        "plannerContext": {
            "userMessage": "test message"
        },
        "toolDefinition": {
            "id": format!("tool-{tool_name}"),
            "type": "PrebuiltToolDefinition",
            "name": tool_name,
            "description": format!("Test tool: {tool_name}")
        },
        "inputValues": input_values,
        "conversationMetadata": {
            "agent": {
                "id": "test-agent",
                "tenantId": "test-tenant",
                "environmentId": "test-env",
                "isPublished": true
            },
            "conversationId": conversation_id
        }
    })
}

/// POST to `url` with optional Authorization header and JSON body.
async fn post_json(
    client: &Client,
    url: &str,
    auth_header: Option<&str>,
    body: Option<Value>,
) -> reqwest::Response {
    let mut req = client.post(url);
    if let Some(h) = auth_header {
        req = req.header("Authorization", h);
    }
    if let Some(b) = body {
        req = req.json(&b);
    } else {
        req = req.header("Content-Type", "application/json").body("");
    }
    req.send().await.expect("HTTP request failed")
}

/// Delete the session file created during a test to avoid state bleed.
fn cleanup_session_file(session_id: &str) {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let path = std::path::PathBuf::from(home)
        .join(".lilith")
        .join("sessions")
        .join(format!("{session_id}.json"));
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// POST /validate
// ---------------------------------------------------------------------------

/// /validate must return 200 + isSuccessful=true in no-auth mode.
#[tokio::test]
async fn test_webhook_validate_returns_200_no_auth_mode() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let resp = post_json(&client, &format!("{base}/validate"), None, None).await;
    assert_eq!(resp.status(), 200, "/validate must return HTTP 200");

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["isSuccessful"].as_bool(), Some(true));
    assert_eq!(body["status"].as_str(), Some("OK"));
}

/// /validate must return isSuccessful=false when no policy is configured.
///
/// An operator who receives isSuccessful=true believes the server is enforcing
/// policy. Without a policy file, all tool calls are fail-closed denied but the
/// engine is not actually evaluating rules — isSuccessful=false makes this
/// explicit so the configuration mistake is caught during initial setup.
#[tokio::test]
async fn test_webhook_validate_returns_not_successful_when_no_policy() {
    let config = Config::default(); // no policies_yaml_path
    let state = WebhookState {
        config: Arc::new(config),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
    };
    let base = start_test_server(state).await;
    let client = Client::new();

    let resp = post_json(&client, &format!("{base}/validate"), None, None).await;
    assert_eq!(resp.status(), 200, "/validate must still return HTTP 200");

    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["isSuccessful"].as_bool(),
        Some(false),
        "isSuccessful must be false when no policy is configured"
    );
    let status = body["status"].as_str().unwrap_or("");
    assert!(
        !status.is_empty() && status != "OK",
        "status must describe the misconfiguration, got: {status}"
    );
}

/// /validate must return 401 when no token is supplied (shared-secret mode).
#[tokio::test]
async fn test_webhook_validate_returns_401_with_no_token() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_with_shared_secret_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let resp = post_json(&client, &format!("{base}/validate"), None, None).await;
    assert_eq!(resp.status(), 401, "missing token must return 401");

    let body: Value = resp.json().await.unwrap();
    assert!(
        body["errorCode"].is_number(),
        "401 must have numeric errorCode"
    );
    assert!(
        body["message"].is_string(),
        "401 must have a message string"
    );
}

/// /validate must return 401 on a malformed token (shared-secret mode).
#[tokio::test]
async fn test_webhook_validate_returns_401_with_invalid_token() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_with_shared_secret_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let resp = post_json(
        &client,
        &format!("{base}/validate"),
        Some("Bearer not.a.real.jwt"),
        None,
    )
    .await;
    assert_eq!(resp.status(), 401, "invalid JWT must return 401");
}

// ---------------------------------------------------------------------------
// POST /analyze-tool-execution — core allow / deny
// ---------------------------------------------------------------------------

/// Allowed tool must return blockAction=false.
#[tokio::test]
async fn test_webhook_analyze_allowed_tool_returns_block_false() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-allow-1", "allowed_tool", json!({"arg": "value"}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(
        json["blockAction"].as_bool(),
        Some(false),
        "allowed tool must return blockAction=false"
    );
}

/// Denied tool must return blockAction=true.
#[tokio::test]
async fn test_webhook_analyze_denied_tool_returns_block_true() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-deny-1", "forbidden_tool", json!({}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(
        json["blockAction"].as_bool(),
        Some(true),
        "denied tool must return blockAction=true"
    );
}

/// Block response must include a non-empty reason string.
#[tokio::test]
async fn test_webhook_analyze_block_includes_human_readable_reason() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-reason-1", "forbidden_tool", json!({}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body),
    )
    .await;

    let json: Value = resp.json().await.unwrap();
    let reason = json["reason"].as_str();
    assert!(
        reason.is_some() && !reason.unwrap().is_empty(),
        "block must include a non-empty reason, got: {json}"
    );
}

/// Block response must include a numeric reasonCode.
#[tokio::test]
async fn test_webhook_analyze_block_includes_reason_code() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-rc-1", "forbidden_tool", json!({}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body),
    )
    .await;

    let json: Value = resp.json().await.unwrap();
    assert!(
        json["reasonCode"].as_i64().is_some(),
        "block response must include a numeric reasonCode"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed security invariants
// ---------------------------------------------------------------------------

/// Missing Authorization header must return HTTP 401 when auth is required.
#[tokio::test]
async fn test_webhook_analyze_no_token_returns_401() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_with_shared_secret_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-no-auth-1", "allowed_tool", json!({}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body),
    )
    .await;

    assert_eq!(resp.status(), 401, "missing token must return 401");
}

/// Invalid JWT must return HTTP 401.
#[tokio::test]
async fn test_webhook_analyze_invalid_token_returns_401() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_with_shared_secret_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-bad-jwt-1", "allowed_tool", json!({}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        Some("Bearer tampered.jwt.here"),
        Some(body),
    )
    .await;

    assert_eq!(resp.status(), 401, "invalid JWT must return 401");
}

/// Malformed JSON body must return HTTP 400.
#[tokio::test]
async fn test_webhook_analyze_malformed_body_returns_400() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let resp = client
        .post(format!("{base}/analyze-tool-execution"))
        .header("Content-Type", "application/json")
        .body("{this is not json}")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        400,
        "malformed JSON body must return HTTP 400"
    );

    let json: Value = resp.json().await.unwrap();
    assert!(
        json["errorCode"].is_number(),
        "400 body must include errorCode"
    );
    assert!(
        json["message"].as_str().is_some(),
        "400 body must include message"
    );
}

/// Tool not in policy must be blocked in fail-closed (BlockParams) mode.
#[tokio::test]
async fn test_webhook_analyze_unknown_tool_blocked_fail_closed() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-unknown-1", "mystery_unlisted_tool", json!({}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(
        json["blockAction"].as_bool(),
        Some(true),
        "tool not in policy must be blocked (fail-closed)"
    );
}

/// No policy loaded must block all tools (fail-closed).
#[tokio::test]
async fn test_webhook_analyze_no_policy_blocks_all_fail_closed() {
    let config = Config::default(); // no policies_yaml_path
    let state = WebhookState {
        config: Arc::new(config),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
    };
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-no-policy-1", "any_tool", json!({}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body),
    )
    .await;

    assert_eq!(resp.status(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(
        json["blockAction"].as_bool(),
        Some(true),
        "no policy must block all tools (fail-closed)"
    );
}

// ---------------------------------------------------------------------------
// Response format validation
// ---------------------------------------------------------------------------

/// Response must be valid JSON (exercised for both allow and deny).
#[tokio::test]
async fn test_webhook_analyze_response_is_valid_json_on_allow() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-json-allow", "allowed_tool", json!({}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body),
    )
    .await;
    let _: Value = resp
        .json()
        .await
        .expect("allow response must be valid JSON");
}

#[tokio::test]
async fn test_webhook_analyze_response_is_valid_json_on_deny() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-json-deny", "forbidden_tool", json!({}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body),
    )
    .await;
    let _: Value = resp.json().await.expect("deny response must be valid JSON");
}

/// Allow response must NOT contain reasonCode or reason (clean JSON).
#[tokio::test]
async fn test_webhook_analyze_allow_response_has_no_extra_fields() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-fields-1", "allowed_tool", json!({}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body),
    )
    .await;

    let json: Value = resp.json().await.unwrap();
    let obj = json.as_object().unwrap();
    assert!(
        obj.contains_key("blockAction"),
        "allow must have blockAction"
    );
    assert!(
        !obj.contains_key("reasonCode"),
        "allow must not have reasonCode"
    );
    assert!(!obj.contains_key("reason"), "allow must not have reason");
}

// ---------------------------------------------------------------------------
// Taint persistence (same conversationId)
// ---------------------------------------------------------------------------

/// Taint added by one request must be visible to the next request in the same
/// conversation. This tests the conversationId → session_id → PersistenceLayer chain.
#[tokio::test]
async fn test_webhook_taint_persists_across_requests_same_conversation() {
    let policy_yaml = r#"
id: webhook-taint-test
customer_id: test
name: Webhook Taint Test
version: 1
static_rules:
  taint_me: ALLOW
  check_me: ALLOW
taint_rules:
  - tool: taint_me
    action: ADD_TAINT
    tag: WEBHOOK_TAINT
  - tool: check_me
    action: CHECK_TAINT
    required_taints: ["WEBHOOK_TAINT"]
    error: "blocked when WEBHOOK_TAINT is active"
resource_rules: []
"#;
    let policy = write_temp_policy(policy_yaml);
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();
    let conv_id = format!("webhook-taint-conv-{}", std::process::id());

    // Request 1: invoke taint_me → adds WEBHOOK_TAINT to the session
    let body1 = analyze_request(&conv_id, "taint_me", json!({}));
    let resp1 = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body1),
    )
    .await;
    let json1: Value = resp1.json().await.unwrap();
    assert_eq!(
        json1["blockAction"].as_bool(),
        Some(false),
        "taint_me must be allowed"
    );

    // Request 2: invoke check_me → must be blocked (WEBHOOK_TAINT is now active)
    let body2 = analyze_request(&conv_id, "check_me", json!({}));
    let resp2 = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body2),
    )
    .await;
    let json2: Value = resp2.json().await.unwrap();
    assert_eq!(
        json2["blockAction"].as_bool(),
        Some(true),
        "check_me must be blocked because WEBHOOK_TAINT persisted from taint_me"
    );

    cleanup_session_file(&conv_id);
}

// ---------------------------------------------------------------------------
// Session isolation (different conversationIds)
// ---------------------------------------------------------------------------

/// Taints from conversation A must NOT affect conversation B.
/// CHECK_TAINT blocks check_tool when ISOLATION_TAINT is active.
/// - Conversation A acquires ISOLATION_TAINT → check_tool BLOCKED.
/// - Conversation B never acquires it → check_tool ALLOWED.
#[tokio::test]
async fn test_webhook_different_conversations_have_isolated_sessions() {
    let policy_yaml = r#"
id: webhook-isolation-test
customer_id: test
name: Webhook Isolation Test
version: 1
static_rules:
  taint_source: ALLOW
  check_tool: ALLOW
taint_rules:
  - tool: taint_source
    action: ADD_TAINT
    tag: ISOLATION_TAINT
  - tool: check_tool
    action: CHECK_TAINT
    required_taints: ["ISOLATION_TAINT"]
    error: "blocked when ISOLATION_TAINT is active"
resource_rules: []
"#;
    let policy = write_temp_policy(policy_yaml);
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();
    let pid = std::process::id();
    let conv_a = format!("webhook-iso-a-{pid}");
    let conv_b = format!("webhook-iso-b-{pid}");

    // Step 1: Add ISOLATION_TAINT to conversation A
    let body_a_taint = analyze_request(&conv_a, "taint_source", json!({}));
    post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body_a_taint),
    )
    .await;

    // Step 2: Conversation A must be blocked for check_tool (taint is active)
    let body_a_check = analyze_request(&conv_a, "check_tool", json!({}));
    let resp_a = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body_a_check),
    )
    .await;
    let json_a: Value = resp_a.json().await.unwrap();
    assert_eq!(
        json_a["blockAction"].as_bool(),
        Some(true),
        "check_tool must be blocked in conversation A (ISOLATION_TAINT is active)"
    );

    // Step 3: Conversation B must NOT be blocked (no taint bleed from A)
    let body_b_check = analyze_request(&conv_b, "check_tool", json!({}));
    let resp_b = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body_b_check),
    )
    .await;
    let json_b: Value = resp_b.json().await.unwrap();
    assert_eq!(
        json_b["blockAction"].as_bool(),
        Some(false),
        "check_tool must be allowed in conversation B: ISOLATION_TAINT from A must not bleed"
    );

    cleanup_session_file(&conv_a);
    cleanup_session_file(&conv_b);
}

// ---------------------------------------------------------------------------
// Concurrent requests (flock serialization)
// ---------------------------------------------------------------------------

/// Multiple concurrent requests for the same conversationId must each return
/// a valid JSON response — the file-lock serialization must not corrupt state.
#[tokio::test]
async fn test_webhook_concurrent_requests_same_conversation_return_valid_json() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Arc::new(Client::new());
    let conv_id = format!("concurrent-conv-{}", std::process::id());

    let mut handles = Vec::new();
    for _ in 0..5 {
        let c = client.clone();
        let b = base.clone();
        let id = conv_id.clone();
        let h = tokio::spawn(async move {
            let body = analyze_request(&id, "allowed_tool", json!({}));
            let resp =
                post_json(&c, &format!("{b}/analyze-tool-execution"), None, Some(body)).await;
            assert_eq!(resp.status(), 200);
            let json: Value = resp.json().await.unwrap();
            assert!(
                json["blockAction"].is_boolean(),
                "blockAction must be a boolean, not corrupted: {json}"
            );
        });
        handles.push(h);
    }

    for h in handles {
        h.await.expect("concurrent request task panicked");
    }

    cleanup_session_file(&conv_id);
}

// ---------------------------------------------------------------------------
// Hardening: body size limit
// ---------------------------------------------------------------------------

/// Bodies larger than 1 MiB must be rejected with HTTP 413 before reaching
/// any handler. This prevents DoS via oversized payloads and ensures the
/// timeout budget is not consumed reading junk data.
#[tokio::test]
async fn test_webhook_analyze_oversized_body_returns_413() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    // 2 MiB — double the 1 MiB limit
    let oversized = "x".repeat(2 * 1024 * 1024);

    let resp = client
        .post(format!("{base}/analyze-tool-execution"))
        .header("Content-Type", "application/json")
        .body(oversized)
        .send()
        .await
        .expect("HTTP request failed");

    assert_eq!(
        resp.status(),
        413,
        "body exceeding 1 MiB limit must return HTTP 413 Payload Too Large"
    );
}

// Note: /validate is NOT tested for oversized bodies because it has no body
// extractor — axum's DefaultBodyLimit only fires when a body is extracted by
// a handler. The MS spec mandates an empty body for /validate, so a large
// body there is not a realistic attack vector. The important protection is on
// /analyze-tool-execution which does parse the body.

// ---------------------------------------------------------------------------
// Hardening: x-ms-correlation-id passthrough
// ---------------------------------------------------------------------------

/// Copilot Studio sends an `x-ms-correlation-id` header for distributed tracing.
/// The webhook must echo it back in the response so Copilot Studio can correlate
/// its logs with the security provider's logs.
#[tokio::test]
async fn test_webhook_analyze_correlation_id_echoed_in_response() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-corr-1", "allowed_tool", json!({}));
    let resp = client
        .post(format!("{base}/analyze-tool-execution"))
        .header("Content-Type", "application/json")
        .header(
            "x-ms-correlation-id",
            "fbac57f1-3b19-4a2b-b69f-a1f2f2c5cc3c",
        )
        .json(&body)
        .send()
        .await
        .expect("HTTP request failed");

    assert_eq!(resp.status(), 200);
    let echoed = resp
        .headers()
        .get("x-ms-correlation-id")
        .and_then(|v| v.to_str().ok());
    assert_eq!(
        echoed,
        Some("fbac57f1-3b19-4a2b-b69f-a1f2f2c5cc3c"),
        "x-ms-correlation-id must be echoed back in the response header"
    );
}

/// /validate must also echo the correlation ID back.
#[tokio::test]
async fn test_webhook_validate_correlation_id_echoed_in_response() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let resp = client
        .post(format!("{base}/validate"))
        .header("Content-Type", "application/json")
        .header("x-ms-correlation-id", "test-trace-id-9876")
        .body("")
        .send()
        .await
        .expect("HTTP request failed");

    assert_eq!(resp.status(), 200);
    let echoed = resp
        .headers()
        .get("x-ms-correlation-id")
        .and_then(|v| v.to_str().ok());
    assert_eq!(
        echoed,
        Some("test-trace-id-9876"),
        "/validate must echo x-ms-correlation-id back in the response"
    );
}

/// Requests without x-ms-correlation-id must work normally (the header is optional).
#[tokio::test]
async fn test_webhook_analyze_missing_correlation_id_is_not_required() {
    let policy = write_temp_policy(default_policy_yaml());
    let state = test_state_no_auth(policy.path());
    let base = start_test_server(state).await;
    let client = Client::new();

    let body = analyze_request("conv-no-corr", "allowed_tool", json!({}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        None,
        Some(body),
    )
    .await;

    assert_eq!(
        resp.status(),
        200,
        "requests without correlation ID must succeed"
    );
    assert!(
        resp.headers().get("x-ms-correlation-id").is_none(),
        "response must not include x-ms-correlation-id if the request had none"
    );
}

// ---------------------------------------------------------------------------
// Shared-secret full HTTP roundtrip (auth acceptance path)
// ---------------------------------------------------------------------------
// These tests generate a valid HS256 JWT client-side and verify that the
// server accepts it end-to-end. This is distinct from the auth unit tests
// (src/server/auth.rs) which test the authenticator in isolation — here we
// verify the full path: header extraction → token validation → handler logic.

/// Build a valid HS256 JWT for use in integration tests.
fn make_test_hs256_token(secret: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = json!({
        "sub": "test-subject",
        "exp": now + 3600,
        "iat": now,
        "iss": "test-issuer"
    });

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("failed to encode test HS256 token")
}

/// A valid shared-secret JWT must be accepted by /validate end-to-end.
///
/// This is the acceptance path: the auth unit tests cover rejection; this test
/// covers the full HTTP roundtrip from a signed JWT to an HTTP 200 response.
#[tokio::test]
async fn test_webhook_shared_secret_valid_token_accepted_by_validate() {
    let secret = "integration-test-shared-secret-32ch";
    let policy = write_temp_policy(default_policy_yaml());
    let state = WebhookState {
        config: Arc::new(Config {
            policies_yaml_path: Some(policy.path().to_path_buf()),
            ..Config::default()
        }),
        audit_log_path: None,
        auth: Arc::new(SharedSecretAuthenticator::new(secret, None)),
    };
    let base = start_test_server(state).await;
    let client = Client::new();

    let token = make_test_hs256_token(secret);
    let resp = post_json(
        &client,
        &format!("{base}/validate"),
        Some(&format!("Bearer {token}")),
        None,
    )
    .await;

    assert_eq!(
        resp.status(),
        200,
        "valid shared-secret token must be accepted by /validate"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["isSuccessful"].as_bool(),
        Some(true),
        "isSuccessful must be true when auth passes and policy is loaded"
    );
}

/// A valid shared-secret JWT must allow a tool call through /analyze-tool-execution.
///
/// End-to-end acceptance path: token signed → accepted → policy evaluated → allow.
#[tokio::test]
async fn test_webhook_shared_secret_valid_token_accepted_by_analyze() {
    let secret = "integration-test-shared-secret-32ch";
    let policy = write_temp_policy(default_policy_yaml());
    let state = WebhookState {
        config: Arc::new(Config {
            policies_yaml_path: Some(policy.path().to_path_buf()),
            ..Config::default()
        }),
        audit_log_path: None,
        auth: Arc::new(SharedSecretAuthenticator::new(secret, None)),
    };
    let base = start_test_server(state).await;
    let client = Client::new();

    let token = make_test_hs256_token(secret);
    let body = analyze_request("conv-auth-roundtrip-1", "allowed_tool", json!({}));
    let resp = post_json(
        &client,
        &format!("{base}/analyze-tool-execution"),
        Some(&format!("Bearer {token}")),
        Some(body),
    )
    .await;

    assert_eq!(
        resp.status(),
        200,
        "valid shared-secret token must reach the policy engine (HTTP 200)"
    );
    let json_body: Value = resp.json().await.unwrap();
    assert_eq!(
        json_body["blockAction"].as_bool(),
        Some(false),
        "allowed_tool must be allowed when valid token is presented"
    );
}
