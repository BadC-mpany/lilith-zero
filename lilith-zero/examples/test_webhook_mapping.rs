#[cfg(feature = "webhook")]
use lilith_zero::config::Config;
#[cfg(feature = "webhook")]
use lilith_zero::server::auth::NoAuthAuthenticator;
#[cfg(feature = "webhook")]
use lilith_zero::server::webhook::WebhookState;
#[cfg(feature = "webhook")]
use std::collections::HashMap;
#[cfg(feature = "webhook")]
use std::path::PathBuf;
#[cfg(feature = "webhook")]
use std::str::FromStr;
#[cfg(feature = "webhook")]
use std::sync::Arc;

#[cfg(feature = "webhook")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("--- Lilith Webhook Mapping Scientist Test ---");

    let agent_id = "5be3e14e-2e46-f111-bec6-7c1e52344333";
    let policy_content = ""; // Empty policy

    let policy_set = cedar_policy::PolicySet::from_str(policy_content).unwrap();
    let mut cedar_policies = HashMap::new();
    cedar_policies.insert(agent_id.to_string(), Arc::new(policy_set));

    println!(
        "Loaded policies for: {:?}",
        cedar_policies.keys().collect::<Vec<_>>()
    );

    let config = Config {
        session_storage_dir: PathBuf::from("/tmp/lilith-webhook-test"),
        ..Default::default()
    };

    let state = WebhookState {
        config: Arc::new(config),
        audit_log_path: None,
        auth: Arc::new(NoAuthAuthenticator),
        policy: None,
        cedar_policies,
    };

    // Simulate do_analyze logic
    let test_agent_id = "5be3e14e-2e46-f111-bec6-7c1e52344333";
    let cedar_policy = state.cedar_policies.get(test_agent_id).cloned();

    println!(
        "Found policy for {}: {}",
        test_agent_id,
        cedar_policy.is_some()
    );

    if !state.cedar_policies.is_empty() && cedar_policy.is_none() {
        println!("RESULT: Would DENY (No policy for agent)");
    } else {
        println!("RESULT: Proceeding to HookHandler");
        // Proceeding to HookHandler with an empty policy set
        let mut handler = lilith_zero::hook::HookHandler::with_policy(
            state.config.clone(),
            None,
            None,
            cedar_policy,
        )
        .unwrap();

        let input = lilith_zero::hook::HookInput {
            session_id: "test-session".to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: Some("test_tool".to_string()),
            tool_input: Some(serde_json::json!({})),
            tool_output: None,
            request_id: Some("req-1".to_string()),
        };

        let exit_code = handler.handle(input).await.unwrap();
        println!("HookHandler Exit Code: {}", exit_code);
        if exit_code == 0 {
            println!("FINAL DECISION: ALLOW");
        } else {
            println!("FINAL DECISION: DENY");
        }
    }

    Ok(())
}

#[cfg(not(feature = "webhook"))]
fn main() {
    println!("This example requires the 'webhook' feature. Run with: cargo run --example test_webhook_mapping --features webhook");
}
