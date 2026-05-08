//! Production payload tests with realistic Copilot Studio requests.
//!
//! These tests verify end-to-end behavior using:
//! - Real Cedar policies from examples/copilot_studio/policies/
//! - Authentic Copilot Studio webhook request structure
//! - Taint persistence across multiple requests in same conversation
//! - Lethal trifecta protection validation

#![cfg(feature = "webhook")]

use lilith_zero::config::Config;
use lilith_zero::engine_core::persistence::PersistenceLayer;
use lilith_zero::hook::HookHandler;
use lilith_zero::server::auth::NoAuthAuthenticator;
use lilith_zero::server::copilot_studio::{to_hook_input, AnalyzeToolExecutionRequest};
use lilith_zero::server::policy_store::PolicyStore;
use lilith_zero::server::webhook::WebhookState;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tempfile::TempDir;
use uuid::Uuid;

// ============================================================================
// Test Fixtures & Helpers
// ============================================================================

const TEST_AGENT_ID: &str = "5be3e14e-2e46-f111-bec6-7c1e52344333";

// Real Cedar resource IDs as they appear in the Cedar policy file.
const TOOL_SEARCH_WEB: &str = "cra65_otpdemo.action.SearchWeb-SearchWeb";
const TOOL_READ_EMAILS: &str = "cra65_otpdemo.action.ReadEmails-ReadEmails";
const TOOL_SEND_EMAIL: &str = "cra65_otpdemo.action.SendEmail-SendEmail";
const TOOL_FETCH_WEBPAGE: &str = "cra65_otpdemo.action.FetchWebpage-FetchWebpage";
const TOOL_EXECUTE_PYTHON: &str = "cra65_otpdemo.action.ExecutePython-ExecutePython";

fn load_test_policy() -> cedar_policy::PolicySet {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("examples/copilot_studio/policies")
        .join("policy_5be3e14e-2e46-f111-bec6-7c1e52344333.cedar");

    let content = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|_| panic!("Failed to read policy file: {:?}", policy_path));

    cedar_policy::PolicySet::from_str(&content).expect("Failed to parse Cedar policy")
}

fn build_payload(
    tool_name: &str,
    tool_id: &str,
    agent_id: &str,
    conversation_id: &str,
    input_values: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "plannerContext": {
            "userMessage": format!("Testing {} tool", tool_name),
            "thought": "Lilith Zero security validation",
            "chatHistory": [],
            "previousToolsOutputs": []
        },
        "toolDefinition": {
            "id": tool_id,
            "type": "ToolDefinition",
            "name": tool_name,
            "description": format!("Mock {} tool", tool_name),
            "inputParameters": [],
            "outputParameters": []
        },
        "inputValues": input_values,
        "conversationMetadata": {
            "agent": {
                "id": agent_id,
                "tenantId": "test-tenant",
                "environmentId": "test-env",
                "name": "otp_demo",
                "isPublished": true
            },
            "conversationId": conversation_id,
            "channelId": "pva-studio"
        }
    })
}

fn create_webhook_state(
    storage_dir: PathBuf,
    cedar_policy: cedar_policy::PolicySet,
) -> WebhookState {
    let config = Config {
        session_storage_dir: storage_dir,
        ..Default::default()
    };
    let mut cedar_map = std::collections::HashMap::new();
    cedar_map.insert(TEST_AGENT_ID.to_string(), Arc::new(cedar_policy));
    WebhookState {
        config: Arc::new(config),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy_store: Arc::new(PolicyStore::from_map(cedar_map, None, None, false)),
        admin_token: None,
    }
}

/// Run a single tool call through HookHandler and return the exit code.
/// handle() manages all locking and persistence internally.
fn run_tool(
    state: &WebhookState,
    storage_dir: PathBuf,
    tool_name: &str,
    tool_id: &str,
    conversation_id: &str,
    input_values: serde_json::Value,
) -> i32 {
    let payload = build_payload(
        tool_name,
        tool_id,
        TEST_AGENT_ID,
        conversation_id,
        input_values,
    );
    let request: AnalyzeToolExecutionRequest =
        serde_json::from_value(payload).expect("valid payload");
    let hook_input = to_hook_input(&request);

    let policy_store = state.policy_store.clone();
    let config = state.config.clone();

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async move {
        let cedar_policy = policy_store.get(TEST_AGENT_ID).await;
        let mut handler = HookHandler::with_policy_and_persistence(
            config,
            None,
            None,
            cedar_policy,
            PersistenceLayer::new(storage_dir),
        )
        .expect("handler creation");
        handler.handle(hook_input).await.expect("handle")
    })
}

// ============================================================================
// Tests
// ============================================================================

/// Verify payload parsing: conversation_id → session_id, tool_definition.id → tool_name.
#[test]
fn test_production_basic_policy_and_tool_execution() {
    let conversation_id = Uuid::new_v4().to_string();

    let payload = build_payload(
        "Search-Web",
        TOOL_SEARCH_WEB,
        TEST_AGENT_ID,
        &conversation_id,
        serde_json::json!({"query": "test query"}),
    );
    let request: AnalyzeToolExecutionRequest =
        serde_json::from_value(payload).expect("valid payload");
    let hook_input = to_hook_input(&request);

    assert_eq!(hook_input.session_id, conversation_id);
    assert_eq!(hook_input.tool_name.as_deref(), Some(TOOL_SEARCH_WEB));
    assert_eq!(hook_input.hook_event_name, "PreToolUse");
}

/// Cedar policy file loads and is non-empty.
#[test]
fn test_production_cedar_policy_loads_correctly() {
    let policy = load_test_policy();
    assert!(!policy.is_empty(), "Cedar policy should be non-empty");
}

/// Lethal trifecta: SearchWeb → ReadEmails → SendEmail must be blocked.
///
/// Each call goes through handle() which manages persistence internally.
/// The pattern mirrors the real webhook: a new HookHandler per request,
/// state loaded from disk each time.
#[test]
fn test_production_lethal_trifecta_persists_across_requests() {
    let policy = load_test_policy();
    let _temp = TempDir::new().expect("temp dir");
    let storage = _temp.path().to_path_buf();
    let state = create_webhook_state(storage.clone(), policy);
    let conv = Uuid::new_v4().to_string();

    // Request 1: SearchWeb — allowed, adds UNTRUSTED_SOURCE.
    let r1 = run_tool(
        &state,
        storage.clone(),
        "Search-Web",
        TOOL_SEARCH_WEB,
        &conv,
        serde_json::json!({"query": "x"}),
    );
    assert_eq!(r1, 0, "SearchWeb should be allowed");

    // Request 2: ReadEmails — allowed, adds ACCESS_PRIVATE.
    let r2 = run_tool(
        &state,
        storage.clone(),
        "Read-Emails",
        TOOL_READ_EMAILS,
        &conv,
        serde_json::json!({"folder": "Inbox"}),
    );
    assert_eq!(r2, 0, "ReadEmails should be allowed");

    // Request 3: SendEmail — blocked by lethal trifecta (both taints present).
    let r3 = run_tool(
        &state,
        storage.clone(),
        "Send-Email",
        TOOL_SEND_EMAIL,
        &conv,
        serde_json::json!({"to": "victim@example.com"}),
    );
    assert_eq!(r3, 2, "SendEmail should be BLOCKED by lethal trifecta");
}

/// Session isolation: conversation A's taints must not bleed into conversation B.
#[test]
fn test_production_session_isolation_between_conversations() {
    let policy = load_test_policy();
    let _temp = TempDir::new().expect("temp dir");
    let storage = _temp.path().to_path_buf();
    let state = create_webhook_state(storage.clone(), policy);

    let conv_a = Uuid::new_v4().to_string();
    let conv_b = Uuid::new_v4().to_string();

    // Conv A: accumulate both taints.
    run_tool(
        &state,
        storage.clone(),
        "Search-Web",
        TOOL_SEARCH_WEB,
        &conv_a,
        serde_json::json!({"query": "x"}),
    );
    run_tool(
        &state,
        storage.clone(),
        "Read-Emails",
        TOOL_READ_EMAILS,
        &conv_a,
        serde_json::json!({"folder": "Inbox"}),
    );

    // Conv A SendEmail must now be blocked.
    let ra = run_tool(
        &state,
        storage.clone(),
        "Send-Email",
        TOOL_SEND_EMAIL,
        &conv_a,
        serde_json::json!({"to": "x@y.com"}),
    );
    assert_eq!(ra, 2, "Conv A SendEmail must be blocked");

    // Conv B has never called any taint-adding tool — SendEmail must be allowed.
    let rb = run_tool(
        &state,
        storage.clone(),
        "Send-Email",
        TOOL_SEND_EMAIL,
        &conv_b,
        serde_json::json!({"to": "clean@example.com"}),
    );
    assert_eq!(rb, 0, "Conv B SendEmail must be allowed (no taints)");
}

/// Allowed tools: each tool in its own clean conversation is permitted.
#[test]
fn test_production_allowed_tools_permitted() {
    let policy = load_test_policy();
    let _temp = TempDir::new().expect("temp dir");
    let storage = _temp.path().to_path_buf();
    let state = create_webhook_state(storage.clone(), policy);

    let cases = [
        (
            "Search-Web",
            TOOL_SEARCH_WEB,
            serde_json::json!({"query": "test"}),
        ),
        (
            "Read-Emails",
            TOOL_READ_EMAILS,
            serde_json::json!({"folder": "Inbox"}),
        ),
        (
            "Send-Email",
            TOOL_SEND_EMAIL,
            serde_json::json!({"to": "ok@example.com"}),
        ),
        (
            "Fetch-Webpage",
            TOOL_FETCH_WEBPAGE,
            serde_json::json!({"url": "https://example.com"}),
        ),
        (
            "Execute-Python",
            TOOL_EXECUTE_PYTHON,
            serde_json::json!({"code": "print('hi')"}),
        ),
    ];

    for (tool_name, tool_id, input) in cases {
        // Fresh conversation per tool — no accumulated taints.
        let conv = Uuid::new_v4().to_string();
        let result = run_tool(&state, storage.clone(), tool_name, tool_id, &conv, input);
        assert_eq!(
            result, 0,
            "{} should be permitted in a clean session",
            tool_name
        );
    }
}
