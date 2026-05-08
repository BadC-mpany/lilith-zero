#[cfg(feature = "webhook")]
mod webhook_mapping {
    use lilith_zero::config::Config;
    use lilith_zero::server::auth::NoAuthAuthenticator;
    use lilith_zero::server::policy_store::PolicyStore;
    use lilith_zero::server::webhook::WebhookState;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::Arc;

    const AGENT_ID: &str = "5be3e14e-2e46-f111-bec6-7c1e52344333";

    fn make_state() -> WebhookState {
        let policy_set = cedar_policy::PolicySet::from_str("").unwrap();
        let mut cedar_map = HashMap::new();
        cedar_map.insert(AGENT_ID.to_string(), Arc::new(policy_set));

        let config = Config {
            session_storage_dir: PathBuf::from("/tmp/lilith-webhook-test"),
            ..Default::default()
        };

        WebhookState {
            config: Arc::new(config),
            audit_log_path: None,
            auth: Arc::new(NoAuthAuthenticator),
            policy_store: Arc::new(PolicyStore::from_map(cedar_map, None, None, false)),
            admin_token: None,
        }
    }

    #[tokio::test]
    async fn known_agent_id_finds_policy() {
        let state = make_state();
        let cedar_policy = state.policy_store.get(AGENT_ID).await;
        assert!(cedar_policy.is_some(), "expected policy for known agent ID");
    }

    #[tokio::test]
    async fn unknown_agent_id_finds_no_policy() {
        let state = make_state();
        let cedar_policy = state.policy_store.get("unknown-id").await;
        assert!(
            cedar_policy.is_none(),
            "expected no policy for unknown agent ID"
        );
    }

    #[tokio::test]
    async fn known_agent_empty_policy_allows() {
        let state = make_state();
        let cedar_policy = state.policy_store.get(AGENT_ID).await;

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
        // An empty Cedar policy set has no permit rules, so Cedar denies by default.
        assert_ne!(
            exit_code, 0,
            "expected denial exit code for empty Cedar policy (no permit rules)"
        );
    }
}
