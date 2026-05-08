//! Integration tests for PolicyStore hot-reload and admin endpoints.
//!
//! # Coverage
//! - PolicyStore: load, reload, lazy-load, concurrent access during reload
//! - `/admin/reload-policies`: auth gate, success path, error path
//! - `/admin/upload-policy`: auth gate, Cedar validation, disk write, reload
//! - `/admin/status`: auth gate, response fields
//! - Background refresh: timer fires and updates in-memory state
//! - End-to-end: policy change visible without server restart

#![cfg(feature = "webhook")]
#![cfg(not(miri))]

use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde_json::Value;
use tempfile::TempDir;
use tokio::net::TcpListener;

use lilith_zero::config::Config;
use lilith_zero::server::auth::NoAuthAuthenticator;
use lilith_zero::server::policy_store::PolicyStore;
use lilith_zero::server::webhook::{build_router, WebhookState};

// ---------------------------------------------------------------------------
// Test Cedar policies
// ---------------------------------------------------------------------------

const CEDAR_ALLOW_TOOL_A: &str = r#"
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"tool-tool_a"
};
"#;

const CEDAR_ALLOW_TOOL_B: &str = r#"
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"tool-tool_b"
};
"#;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_cedar(dir: &std::path::Path, agent_id: &str, content: &str) {
    let path = dir.join(format!("{agent_id}.cedar"));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

fn remove_cedar(dir: &std::path::Path, agent_id: &str) {
    let _ = std::fs::remove_file(dir.join(format!("{agent_id}.cedar")));
}

async fn start_server(state: WebhookState) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://127.0.0.1:{}", addr.port())
}

fn analyze_body(conversation_id: &str, agent_id: &str, tool_name: &str) -> Value {
    serde_json::json!({
        "plannerContext": {"userMessage": "test"},
        "toolDefinition": {
            "id": format!("tool-{tool_name}"),
            "type": "PrebuiltToolDefinition",
            "name": tool_name,
            "description": "test tool"
        },
        "inputValues": {},
        "conversationMetadata": {
            "agent": {
                "id": agent_id,
                "tenantId": "t",
                "environmentId": "e",
                "isPublished": true
            },
            "conversationId": conversation_id
        }
    })
}

async fn post_analyze(client: &Client, base: &str, agent_id: &str, tool: &str) -> bool {
    let resp = client
        .post(format!("{base}/analyze-tool-execution"))
        .json(&analyze_body("conv-1", agent_id, tool))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    // blockAction=false means ALLOW
    !body["blockAction"].as_bool().unwrap_or(true)
}

async fn admin_reload(client: &Client, base: &str, token: &str) -> reqwest::Response {
    client
        .post(format!("{base}/admin/reload-policies"))
        .header("x-admin-token", token)
        .send()
        .await
        .unwrap()
}

async fn admin_status(client: &Client, base: &str, token: &str) -> reqwest::Response {
    client
        .get(format!("{base}/admin/status"))
        .header("x-admin-token", token)
        .send()
        .await
        .unwrap()
}

async fn upload_policy(
    client: &Client,
    base: &str,
    token: &str,
    agent_id: &str,
    body: &str,
) -> reqwest::Response {
    client
        .post(format!("{base}/admin/upload-policy?agent_id={agent_id}"))
        .header("x-admin-token", token)
        .header("content-type", "text/plain")
        .body(body.to_string())
        .send()
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Admin endpoint security
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_reload_requires_token_when_configured() {
    let tmp = TempDir::new().unwrap();
    write_cedar(tmp.path(), "agent-1", CEDAR_ALLOW_TOOL_A);

    let policy_store = Arc::new(
        PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
            .await
            .unwrap(),
    );
    let state = WebhookState {
        config: Arc::new(Config {
            session_storage_dir: tmp.path().to_path_buf(),
            ..Default::default()
        }),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store,
        admin_token: Some("secret-admin-token".to_string()),
    };
    let base = start_server(state).await;
    let client = Client::new();

    // No token → 403
    let r = client
        .post(format!("{base}/admin/reload-policies"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "missing token must be rejected");

    // Wrong token → 403
    let r = admin_reload(&client, &base, "wrong-token").await;
    assert_eq!(r.status(), 403, "wrong token must be rejected");

    // Correct token → 200
    let r = admin_reload(&client, &base, "secret-admin-token").await;
    assert_eq!(r.status(), 200, "correct token must succeed");
}

#[tokio::test]
async fn test_admin_reload_disabled_when_no_token_configured() {
    let tmp = TempDir::new().unwrap();
    let policy_store = Arc::new(PolicyStore::empty());
    let state = WebhookState {
        config: Arc::new(Config {
            session_storage_dir: tmp.path().to_path_buf(),
            ..Default::default()
        }),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store,
        admin_token: None, // no token configured
    };
    let base = start_server(state).await;
    let client = Client::new();

    let r = admin_reload(&client, &base, "any-token").await;
    assert_eq!(r.status(), 403, "admin endpoint must be disabled when no token configured");
    let body: Value = r.json().await.unwrap();
    assert!(body["error"].as_str().unwrap_or("").contains("disabled"));
}

#[tokio::test]
async fn test_admin_status_requires_token() {
    let tmp = TempDir::new().unwrap();
    let policy_store = Arc::new(PolicyStore::empty());
    let state = WebhookState {
        config: Arc::new(Config {
            session_storage_dir: tmp.path().to_path_buf(),
            ..Default::default()
        }),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store,
        admin_token: Some("admin-secret".to_string()),
    };
    let base = start_server(state).await;
    let client = Client::new();

    let r = admin_status(&client, &base, "wrong").await;
    assert_eq!(r.status(), 403);

    let r = admin_status(&client, &base, "admin-secret").await;
    assert_eq!(r.status(), 200);
}

// ---------------------------------------------------------------------------
// Hot-reload end-to-end
// ---------------------------------------------------------------------------

/// Policy update visible without server restart: write file → call reload → new rule enforced.
#[tokio::test]
async fn test_hot_reload_new_agent_policy_becomes_active() {
    let tmp = TempDir::new().unwrap();
    write_cedar(tmp.path(), "agent-1", CEDAR_ALLOW_TOOL_A);

    let policy_store = Arc::new(
        PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
            .await
            .unwrap(),
    );
    let state = WebhookState {
        config: Arc::new(Config {
            session_storage_dir: tmp.path().to_path_buf(),
            ..Default::default()
        }),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store,
        admin_token: Some("tok".to_string()),
    };
    let base = start_server(state).await;
    let client = Client::new();

    // Before reload: agent-2 has no policy → denied
    assert!(
        !post_analyze(&client, &base, "agent-2", "tool_b").await,
        "agent-2 must be denied before its policy is loaded"
    );

    // Write agent-2's policy file
    write_cedar(tmp.path(), "agent-2", CEDAR_ALLOW_TOOL_B);

    // Call reload
    let r = admin_reload(&client, &base, "tok").await;
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["reloaded"].as_u64(), Some(2), "should report 2 policies after reload");

    // After reload: agent-2 can now use tool_b
    assert!(
        post_analyze(&client, &base, "agent-2", "tool_b").await,
        "agent-2 must be allowed after policy reload"
    );

    // agent-1 still works
    assert!(
        post_analyze(&client, &base, "agent-1", "tool_a").await,
        "agent-1 must still be allowed after reload"
    );
}

/// Policy removal: delete file → reload → agent is denied.
#[tokio::test]
async fn test_hot_reload_removed_policy_denies_agent() {
    let tmp = TempDir::new().unwrap();
    write_cedar(tmp.path(), "agent-1", CEDAR_ALLOW_TOOL_A);
    write_cedar(tmp.path(), "agent-2", CEDAR_ALLOW_TOOL_B);

    let policy_store = Arc::new(
        PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
            .await
            .unwrap(),
    );
    let state = WebhookState {
        config: Arc::new(Config {
            session_storage_dir: tmp.path().to_path_buf(),
            ..Default::default()
        }),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store,
        admin_token: Some("tok".to_string()),
    };
    let base = start_server(state).await;
    let client = Client::new();

    // Baseline: both agents work
    assert!(post_analyze(&client, &base, "agent-1", "tool_a").await);
    assert!(post_analyze(&client, &base, "agent-2", "tool_b").await);

    // Remove agent-2's policy file and reload
    remove_cedar(tmp.path(), "agent-2");
    let r = admin_reload(&client, &base, "tok").await;
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["reloaded"].as_u64(), Some(1), "should report 1 policy after removal");

    // agent-2 now denied
    assert!(
        !post_analyze(&client, &base, "agent-2", "tool_b").await,
        "agent-2 must be denied after its policy is removed"
    );

    // agent-1 unaffected
    assert!(post_analyze(&client, &base, "agent-1", "tool_a").await);
}

/// Reload failure (policy_dir missing) returns 500, does not corrupt in-memory state.
#[tokio::test]
async fn test_hot_reload_failure_preserves_existing_policies() {
    let tmp = TempDir::new().unwrap();
    write_cedar(tmp.path(), "agent-1", CEDAR_ALLOW_TOOL_A);

    let policy_store = Arc::new(
        PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
            .await
            .unwrap(),
    );
    let state = WebhookState {
        config: Arc::new(Config {
            session_storage_dir: tmp.path().to_path_buf(),
            ..Default::default()
        }),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store,
        admin_token: Some("tok".to_string()),
    };
    let base = start_server(state).await;
    let client = Client::new();

    // agent-1 allowed
    assert!(post_analyze(&client, &base, "agent-1", "tool_a").await);

    // Inject an invalid Cedar file to force a parse error on reload
    let bad_path = tmp.path().join("bad-agent.cedar");
    std::fs::write(&bad_path, "this is not valid cedar syntax !!!").unwrap();

    let r = admin_reload(&client, &base, "tok").await;
    // The reload fails due to parse error → 500
    assert_eq!(r.status(), 500, "bad Cedar file must cause reload to fail");

    // Existing policies survive the failed reload
    assert!(
        post_analyze(&client, &base, "agent-1", "tool_a").await,
        "existing policies must survive a failed reload"
    );
}

// ---------------------------------------------------------------------------
// Admin status endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_status_reports_policy_count() {
    let tmp = TempDir::new().unwrap();
    write_cedar(tmp.path(), "agent-1", CEDAR_ALLOW_TOOL_A);
    write_cedar(tmp.path(), "agent-2", CEDAR_ALLOW_TOOL_B);

    let policy_store = Arc::new(
        PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
            .await
            .unwrap(),
    );
    let state = WebhookState {
        config: Arc::new(Config {
            session_storage_dir: tmp.path().to_path_buf(),
            ..Default::default()
        }),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store,
        admin_token: Some("tok".to_string()),
    };
    let base = start_server(state).await;
    let client = Client::new();

    let r = admin_status(&client, &base, "tok").await;
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["cedar_policies"].as_u64(), Some(2));
    assert!(body["loaded_secs_ago"].as_u64().is_some());
    assert!(body["last_reload_ms"].as_u64().is_some());
}

// ---------------------------------------------------------------------------
// Lazy loading
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_lazy_load_picks_up_new_agent_on_first_access() {
    let tmp = TempDir::new().unwrap();

    // Start with empty store, lazy_load=true, policy_dir pointing at tmp
    let policy_store = Arc::new(PolicyStore::from_map(
        std::collections::HashMap::new(),
        None,
        Some(tmp.path().to_path_buf()),
        true,
    ));
    let state = WebhookState {
        config: Arc::new(Config {
            session_storage_dir: tmp.path().to_path_buf(),
            ..Default::default()
        }),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store,
        admin_token: None,
    };
    let base = start_server(state).await;
    let client = Client::new();

    // File doesn't exist → denied
    assert!(!post_analyze(&client, &base, "agent-1", "tool_a").await);

    // Write the file
    write_cedar(tmp.path(), "agent-1", CEDAR_ALLOW_TOOL_A);

    // First access triggers lazy load → allowed
    assert!(
        post_analyze(&client, &base, "agent-1", "tool_a").await,
        "lazy load must pick up the newly written policy on first access"
    );
}

// ---------------------------------------------------------------------------
// Concurrent reload safety
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_requests_during_reload_stay_consistent() {
    let tmp = TempDir::new().unwrap();
    write_cedar(tmp.path(), "agent-1", CEDAR_ALLOW_TOOL_A);
    write_cedar(tmp.path(), "agent-2", CEDAR_ALLOW_TOOL_B);

    let policy_store = Arc::new(
        PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
            .await
            .unwrap(),
    );
    let state = WebhookState {
        config: Arc::new(Config {
            session_storage_dir: tmp.path().to_path_buf(),
            ..Default::default()
        }),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store,
        admin_token: Some("tok".to_string()),
    };
    let base = Arc::new(start_server(state).await);
    let client = Arc::new(Client::new());

    // Fire concurrent tool calls and a reload simultaneously.
    // Each response must be a valid JSON object (no panics, no corrupted state).
    let mut handles = vec![];

    for i in 0..10 {
        let c = client.clone();
        let b = base.clone();
        let agent = if i % 2 == 0 { "agent-1" } else { "agent-2" };
        let tool = if i % 2 == 0 { "tool_a" } else { "tool_b" };
        handles.push(tokio::spawn(async move {
            let resp = c
                .post(format!("{b}/analyze-tool-execution"))
                .json(&analyze_body(&format!("conv-{i}"), agent, tool))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "concurrent request must return 200");
            let body: Value = resp.json().await.unwrap();
            assert!(
                body.get("blockAction").is_some(),
                "response must contain blockAction"
            );
        }));
    }

    // Fire a reload in parallel
    let c = client.clone();
    let b = base.clone();
    handles.push(tokio::spawn(async move {
        let r = admin_reload(&c, &b, "tok").await;
        assert_eq!(r.status(), 200, "reload during concurrent requests must succeed");
    }));

    for h in handles {
        h.await.expect("task panicked");
    }
}

// ---------------------------------------------------------------------------
// Reload response shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_reload_response_has_expected_fields() {
    let tmp = TempDir::new().unwrap();
    write_cedar(tmp.path(), "agent-1", CEDAR_ALLOW_TOOL_A);

    let policy_store = Arc::new(
        PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
            .await
            .unwrap(),
    );
    let state = WebhookState {
        config: Arc::new(Config {
            session_storage_dir: tmp.path().to_path_buf(),
            ..Default::default()
        }),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store,
        admin_token: Some("tok".to_string()),
    };
    let base = start_server(state).await;
    let client = Client::new();

    let r = admin_reload(&client, &base, "tok").await;
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.unwrap();

    assert!(body["reloaded"].as_u64().is_some(), "must include 'reloaded' count");
    assert!(body["elapsed_ms"].as_u64().is_some(), "must include 'elapsed_ms'");
    assert!(body.get("has_legacy").is_some(), "must include 'has_legacy'");

    // Reload should be fast: policy parsing + swap should complete well under 500ms
    let elapsed = body["elapsed_ms"].as_u64().unwrap();
    assert!(
        elapsed < 500,
        "reload should complete in <500ms, got {elapsed}ms"
    );
}

// ---------------------------------------------------------------------------
// Background refresh (timer-based)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_background_refresh_picks_up_new_policy() {
    let tmp = TempDir::new().unwrap();
    write_cedar(tmp.path(), "agent-1", CEDAR_ALLOW_TOOL_A);

    let policy_store = Arc::new(
        PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
            .await
            .unwrap(),
    );

    let store = policy_store.clone();
    // Fast 100ms refresh interval for testing
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(100));
        ticker.tick().await; // skip immediate tick
        loop {
            ticker.tick().await;
            let _ = store.reload().await;
        }
    });

    // Write agent-2's policy while the background task is running
    write_cedar(tmp.path(), "agent-2", CEDAR_ALLOW_TOOL_B);

    // Wait for at least one refresh cycle
    tokio::time::sleep(Duration::from_millis(300)).await;

    // agent-2 should now be visible without an explicit reload
    assert!(
        policy_store.get("agent-2").await.is_some(),
        "background refresh must have picked up the new policy file"
    );
}

// ---------------------------------------------------------------------------
// POST /admin/upload-policy
// ---------------------------------------------------------------------------

fn make_upload_state(policy_dir: std::path::PathBuf, session_dir: std::path::PathBuf) -> WebhookState {
    // Start with an empty store pointing at policy_dir so uploads land there
    // and reload can find them.
    let policy_store = Arc::new(PolicyStore::from_map(
        std::collections::HashMap::new(),
        None,
        Some(policy_dir.clone()),
        false,
    ));
    WebhookState {
        config: Arc::new(Config {
            session_storage_dir: session_dir,
            ..Default::default()
        }),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store,
        admin_token: Some("tok".to_string()),
    }
}

/// Missing / wrong token → 403, file must not be written.
#[tokio::test]
async fn test_upload_policy_requires_token() {
    let tmp = TempDir::new().unwrap();
    let state = make_upload_state(tmp.path().to_path_buf(), tmp.path().to_path_buf());
    let base = start_server(state).await;
    let client = Client::new();

    // No token
    let r = client
        .post(format!("{base}/admin/upload-policy?agent_id=agent-1"))
        .header("content-type", "text/plain")
        .body(CEDAR_ALLOW_TOOL_A)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert!(!tmp.path().join("agent-1.cedar").exists(), "file must not be written on auth failure");

    // Wrong token
    let r = upload_policy(&client, &base, "wrong", "agent-1", CEDAR_ALLOW_TOOL_A).await;
    assert_eq!(r.status(), 403);
    assert!(!tmp.path().join("agent-1.cedar").exists());
}

/// Missing agent_id query param → 400.
#[tokio::test]
async fn test_upload_policy_requires_agent_id() {
    let tmp = TempDir::new().unwrap();
    let state = make_upload_state(tmp.path().to_path_buf(), tmp.path().to_path_buf());
    let base = start_server(state).await;
    let client = Client::new();

    let r = client
        .post(format!("{base}/admin/upload-policy"))
        .header("x-admin-token", "tok")
        .header("content-type", "text/plain")
        .body(CEDAR_ALLOW_TOOL_A)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let body: Value = r.json().await.unwrap();
    assert!(body["error"].as_str().unwrap_or("").contains("agent_id"));
}

/// Invalid Cedar syntax → 400, file must not be written.
#[tokio::test]
async fn test_upload_policy_rejects_invalid_cedar() {
    let tmp = TempDir::new().unwrap();
    let state = make_upload_state(tmp.path().to_path_buf(), tmp.path().to_path_buf());
    let base = start_server(state).await;
    let client = Client::new();

    let r = upload_policy(&client, &base, "tok", "agent-1", "this is NOT valid cedar!!!").await;
    assert_eq!(r.status(), 400);

    let body: Value = r.json().await.unwrap();
    assert!(body["error"].as_str().unwrap_or("").contains("Cedar"), "error must mention Cedar");

    // File must not have been written
    assert!(!tmp.path().join("agent-1.cedar").exists(), "invalid policy must not be written to disk");
}

/// Valid upload → file on disk + policy active in memory.
#[tokio::test]
async fn test_upload_policy_writes_file_and_reloads() {
    let tmp = TempDir::new().unwrap();
    let state = make_upload_state(tmp.path().to_path_buf(), tmp.path().to_path_buf());
    let base = start_server(state).await;
    let client = Client::new();

    // Before upload: agent-1 denied
    assert!(!post_analyze(&client, &base, "agent-1", "tool_a").await);

    let r = upload_policy(&client, &base, "tok", "agent-1", CEDAR_ALLOW_TOOL_A).await;
    assert_eq!(r.status(), 200);

    let body: Value = r.json().await.unwrap();
    assert_eq!(body["uploaded"].as_str(), Some("agent-1"));
    assert!(body["reloaded"].as_u64().is_some());
    assert!(body["elapsed_ms"].as_u64().is_some());

    // File must be on disk
    let written = tmp.path().join("agent-1.cedar");
    assert!(written.exists(), "policy file must be written to disk");
    let content = std::fs::read_to_string(&written).unwrap();
    assert!(content.contains("tool_a"), "file content must match uploaded policy");

    // Policy must be active in memory immediately
    assert!(
        post_analyze(&client, &base, "agent-1", "tool_a").await,
        "uploaded policy must be active after upload"
    );
}

/// Uploading a second time for the same agent overwrites the file and reloads.
#[tokio::test]
async fn test_upload_policy_overwrites_existing() {
    let tmp = TempDir::new().unwrap();
    let state = make_upload_state(tmp.path().to_path_buf(), tmp.path().to_path_buf());
    let base = start_server(state).await;
    let client = Client::new();

    // First upload: allow tool_a
    let r = upload_policy(&client, &base, "tok", "agent-1", CEDAR_ALLOW_TOOL_A).await;
    assert_eq!(r.status(), 200);
    assert!(post_analyze(&client, &base, "agent-1", "tool_a").await, "tool_a must be allowed");
    assert!(!post_analyze(&client, &base, "agent-1", "tool_b").await, "tool_b must be denied");

    // Second upload: replace with policy that allows tool_b instead
    let r = upload_policy(&client, &base, "tok", "agent-1", CEDAR_ALLOW_TOOL_B).await;
    assert_eq!(r.status(), 200);

    // After overwrite: tool_b allowed, tool_a denied
    assert!(!post_analyze(&client, &base, "agent-1", "tool_a").await, "tool_a must be denied after overwrite");
    assert!(post_analyze(&client, &base, "agent-1", "tool_b").await, "tool_b must be allowed after overwrite");
}
