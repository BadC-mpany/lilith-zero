//! Integration tests for Security Core Policy Enforcement
//! Covers:
//! - Fail-Closed default behavior (No Policy)
//! - Lethal Trifecta protection
//! - Resource Taint tracking

use lilith_zero::config::{Config, SecurityLevel};
use lilith_zero::engine_core::crypto::CryptoSigner;
use lilith_zero::engine_core::events::{SecurityDecision, SecurityEvent};
use lilith_zero::engine_core::models::{PolicyDefinition, PolicyRule, ResourceRule};
use lilith_zero::engine_core::security_core::SecurityCore;
use lilith_zero::engine_core::taint::Tainted;
use lilith_zero::engine_core::types::TaintedString;
use std::collections::HashMap;
use std::sync::Arc;

// --- Helpers ---

fn create_core_with_defaults() -> SecurityCore {
    if cfg!(miri) {
        eprintln!("Running Miri: SecurityCore Test Setup");
    }
    let config = Arc::new(Config::default());
    let signer = CryptoSigner::try_new().expect("Failed to create signer");
    SecurityCore::new(config, signer, None).expect("Failed to init core")
}

fn create_security_event(tool: &str, session_token: &str) -> SecurityEvent {
    SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("req".to_string()),
        tool_name: TaintedString::new(tool.to_string()),
        arguments: Tainted::new(serde_json::Value::Null, vec![]),
        session_token: Some(session_token.to_string()),
    }
}

fn create_test_policy(protect_trifecta: bool) -> PolicyDefinition {
    let mut static_rules = HashMap::new();
    static_rules.insert("read_db".to_string(), "ALLOW".to_string());
    static_rules.insert("fetch_url".to_string(), "ALLOW".to_string());
    static_rules.insert("send_email".to_string(), "ALLOW".to_string());
    static_rules.insert("post_api".to_string(), "ALLOW".to_string());
    static_rules.insert("conditional_access".to_string(), "ALLOW".to_string());

    // Define rules that add specific taints
    let taint_rules = vec![
        ("read_db", "ACCESS_PRIVATE"),
        ("fetch_url", "UNTRUSTED_SOURCE"),
        ("send_email", "EXFILTRATION"),
        ("post_api", "EXFILTRATION"),
    ]
    .into_iter()
    .map(|(tool, tag)| PolicyRule {
        tool: Some(tool.to_string()),
        tool_class: None,
        action: "ADD_TAINT".to_string(),
        tag: Some(tag.to_string()),
        forbidden_tags: None,
        required_taints: None,
        error: None,
        match_args: None,
        pattern: None,
        exceptions: None,
    })
    .collect();

    PolicyDefinition {
        id: "test-policy".to_string(),
        customer_id: "test-customer".to_string(),
        name: "Test Policy".to_string(),
        description: None,
        schema_version: None,
        version: 1,
        static_rules,
        taint_rules,
        created_at: None,
        resource_rules: vec![
            // Simplified for brevity, logic remains valid
            ResourceRule {
                uri_pattern: "file:///private/*".to_string(),
                action: "ALLOW".to_string(),
                exceptions: None,
                taints_to_add: Some(vec!["ACCESS_PRIVATE".to_string()]),
            },
            ResourceRule {
                uri_pattern: "http*".to_string(),
                action: "ALLOW".to_string(),
                exceptions: None,
                taints_to_add: Some(vec!["UNTRUSTED_SOURCE".to_string()]),
            },
        ],
        protect_lethal_trifecta: protect_trifecta,
        tool_classes: vec![
            ("send_email".to_string(), vec!["EXFILTRATION".to_string()]),
            ("post_api".to_string(), vec!["EXFILTRATION".to_string()]),
        ]
        .into_iter()
        .collect(),
        rate_limit: None,
        replay_window_secs: 0,
        pin_mode: None,
    }
}

// --- Tests ---

#[tokio::test]
async fn test_fail_closed_no_policy() {
    let mut core = create_core_with_defaults(); // Default is BlockParams
    let token = core.session_id.clone();

    // 1. Attempt Tool Call without Policy
    let event = create_security_event("any_tool", &token);
    let decision = core.evaluate(event).await;

    // 2. Assert Deny
    match decision {
        SecurityDecision::Deny { reason, .. } => {
            assert!(reason.contains("No security policy loaded"));
        }
        _ => panic!("FAIL: Expected Fail-Closed Deny, got {:?}", decision),
    }
}

#[tokio::test]
async fn test_audit_only_allow() {
    let config = Config {
        security_level: SecurityLevel::AuditOnly,
        ..Config::default()
    };

    let signer = CryptoSigner::try_new().unwrap();
    let mut core = SecurityCore::new(Arc::new(config), signer, None).unwrap();
    let token = core.session_id.clone();

    // 1. Attempt Tool Call with AuditOnly + No Policy
    let event = create_security_event("any_tool", &token);
    let decision = core.evaluate(event).await;

    // 2. Assert Allow
    match decision {
        SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {}
        _ => panic!("FAIL: Expected AuditOnly Allow, got {:?}", decision),
    }
}

#[tokio::test]
async fn test_lethal_trifecta_enforcement() {
    let mut core = create_core_with_defaults();
    core.set_policy(create_test_policy(true)); // Protection ON
    let token = core.session_id.clone();

    // 1. Access Private Data
    let _ = core
        .evaluate(create_security_event("read_db", &token))
        .await;

    // 2. Access Untrusted Source
    let _ = core
        .evaluate(create_security_event("fetch_url", &token))
        .await;

    // 3. Attempt Exfiltration (Should be BLOCKED)
    let decision = core
        .evaluate(create_security_event("send_email", &token))
        .await;

    match decision {
        SecurityDecision::Deny { reason, .. } => {
            assert!(reason.contains("lethal trifecta"));
        }
        _ => panic!("FAIL: Expected Lethal Trifecta Block, got {:?}", decision),
    }
}

#[tokio::test]
async fn test_lethal_trifecta_disabled() {
    let mut core = create_core_with_defaults();
    core.set_policy(create_test_policy(false)); // Protection OFF
    let token = core.session_id.clone();

    // 1. Trigger Trifecta Conditions
    let _ = core
        .evaluate(create_security_event("read_db", &token))
        .await;
    let _ = core
        .evaluate(create_security_event("fetch_url", &token))
        .await;

    // 2. Attempt Exfiltration (Should be ALLOWED)
    let decision = core
        .evaluate(create_security_event("send_email", &token))
        .await;

    match decision {
        SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {}
        _ => panic!(
            "FAIL: Expected Allow (Protection Disabled), got {:?}",
            decision
        ),
    }
}

#[tokio::test]
async fn test_resource_trifecta_contribution() {
    let mut core = create_core_with_defaults();
    core.set_policy(create_test_policy(true));
    let token = core.session_id.clone();

    // 1. Read Private Resource
    let res_event = SecurityEvent::ResourceRequest {
        request_id: serde_json::Value::String("1".to_string()),
        uri: TaintedString::new("file:///private/data.txt".to_string()),
        session_token: Some(token.clone()),
    };
    let _ = core.evaluate(res_event).await;

    // 2. Read Untrusted Resource
    let http_event = SecurityEvent::ResourceRequest {
        request_id: serde_json::Value::String("2".to_string()),
        uri: TaintedString::new("http://evil.com".to_string()),
        session_token: Some(token.clone()),
    };
    let _ = core.evaluate(http_event).await;

    // 3. Exfiltrate (Blocked)
    let decision = core
        .evaluate(create_security_event("post_api", &token))
        .await;

    match decision {
        SecurityDecision::Deny { reason, .. } => {
            assert!(reason.contains("lethal trifecta"));
        }
        _ => panic!(
            "FAIL: Expected Mixed-Source Trifecta Block, got {:?}",
            decision
        ),
    }
}

#[tokio::test]
async fn test_argument_matching() {
    let mut core = create_core_with_defaults();
    let config = Config {
        security_level: SecurityLevel::BlockParams,
        ..Config::default()
    };
    core.config = Arc::new(config);

    // Create a policy with ToolArgsMatch logic
    // We want to ALLOW "us-west-1" and BLOCK "us-east-1".
    // Since we added conditional_access to static rules as ALLOW, it's allowed by default.
    // We add a rule to BLOCK if region == "us-east-1".
    let condition =
        lilith_zero::engine_core::models::LogicCondition::ToolArgsMatch(serde_json::json!({
            "region": "us-east-1"
        }));

    let mut policy = create_test_policy(false);
    policy.taint_rules.push(PolicyRule {
        tool: Some("conditional_access".to_string()),
        tool_class: None,
        action: "BLOCK".to_string(),
        tag: None,
        forbidden_tags: None,
        required_taints: None,
        error: Some("Region blocked".to_string()),
        match_args: None,
        pattern: Some(condition),
        exceptions: None,
    });

    core.set_policy(policy);
    let token = core.session_id.clone();

    // 1. Correct Argument (us-west-1) -> Should ALLOW (by static rule, no block match)
    let args_good = Tainted::new(serde_json::json!({"region": "us-west-1"}), vec![]);
    let event_good = SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("1".to_string()),
        tool_name: TaintedString::new("conditional_access".to_string()),
        arguments: args_good,
        session_token: Some(token.clone()),
    };

    let decision = core.evaluate(event_good).await;
    match decision {
        SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {}
        _ => panic!("FAIL: Expected Allow for matching arg, got {:?}", decision),
    }

    // 2. Incorrect Argument (us-east-1) -> Should DENY (by dynamic block rule)
    let args_bad = Tainted::new(serde_json::json!({"region": "us-east-1"}), vec![]);
    let event_bad = SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("2".to_string()),
        tool_name: TaintedString::new("conditional_access".to_string()),
        arguments: args_bad,
        session_token: Some(token.clone()),
    };

    let decision_bad = core.evaluate(event_bad).await;
    match decision_bad {
        SecurityDecision::Deny { reason, .. } => assert!(reason.contains("Region blocked")),
        _ => panic!(
            "FAIL: Expected Deny for non-matching arg, got {:?}",
            decision_bad
        ),
    }
}

#[tokio::test]
async fn test_wildcard_resource_access() {
    let mut core = create_core_with_defaults();
    // Policy has: file:///private/* (ALLOW) and http* (ALLOW)
    // We add a specific rule for valid_log/*.log
    let mut policy = create_test_policy(false);
    policy.resource_rules.push(ResourceRule {
        uri_pattern: "file:///logs/*.log".to_string(),
        action: "ALLOW".to_string(),
        exceptions: None,
        taints_to_add: None,
    });
    policy.resource_rules.push(ResourceRule {
        uri_pattern: "*".to_string(),
        action: "BLOCK".to_string(), // Explicit deny all else
        exceptions: None,
        taints_to_add: None,
    });

    core.set_policy(policy);
    let token = core.session_id.clone();

    // 1. Matching Wildcard
    let event_log = SecurityEvent::ResourceRequest {
        request_id: serde_json::Value::String("1".to_string()),
        uri: TaintedString::new("file:///logs/system.log".to_string()),
        session_token: Some(token.clone()),
    };
    match core.evaluate(event_log).await {
        SecurityDecision::AllowWithTransforms { .. } => {}
        d => panic!("FAIL: Expected Allow for *.log, got {:?}", d),
    }

    // 2. Non-Matching Extension (Blocked by Catch-All)
    let event_exe = SecurityEvent::ResourceRequest {
        request_id: serde_json::Value::String("2".to_string()),
        uri: TaintedString::new("file:///logs/malware.exe".to_string()),
        session_token: Some(token.clone()),
    };
    match core.evaluate(event_exe).await {
        SecurityDecision::Deny { reason, .. } => assert!(reason.contains("blocked by rule")),
        d => panic!("FAIL: Expected Block for .exe, got {:?}", d),
    }
}

// ─── Rate Limiting ──────────────────────────────────────────────────────────

fn make_policy_with_rate_limit(
    max_session: Option<u32>,
    max_per_min: Option<u32>,
) -> PolicyDefinition {
    let mut static_rules = HashMap::new();
    static_rules.insert("ping".to_string(), "ALLOW".to_string());
    PolicyDefinition {
        id: "rate-test".to_string(),
        customer_id: "test".to_string(),
        name: "Rate Test".to_string(),
        description: None,
        schema_version: None,
        version: 1,
        static_rules,
        taint_rules: vec![],
        created_at: None,
        resource_rules: vec![],
        protect_lethal_trifecta: false,
        tool_classes: Default::default(),
        rate_limit: Some(lilith_zero::engine_core::models::RateLimit {
            max_calls_per_session: max_session,
            max_calls_per_minute: max_per_min,
        }),
        replay_window_secs: 0,
        pin_mode: None,
    }
}

fn tool_event_id(tool: &str, id: &str, session: &str) -> SecurityEvent {
    SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String(id.to_string()),
        tool_name: TaintedString::new(tool.to_string()),
        arguments: Tainted::new(serde_json::Value::Null, vec![]),
        session_token: Some(session.to_string()),
    }
}

#[tokio::test]
async fn test_rate_limit_session_cap() {
    let mut core = create_core_with_defaults();
    core.validate_session_tokens = false;
    core.set_policy(make_policy_with_rate_limit(Some(2), None));

    // First two calls should be allowed.
    for i in 0..2u32 {
        let ev = tool_event_id("ping", &i.to_string(), "sess");
        if let SecurityDecision::Deny { .. } = core.evaluate(ev).await {
            panic!("call {} should be allowed", i);
        }
    }
    // Third call exceeds session cap.
    let ev = tool_event_id("ping", "3", "sess");
    match core.evaluate(ev).await {
        SecurityDecision::Deny { reason, .. } => {
            assert!(
                reason.contains("Session call limit exceeded"),
                "got: {}",
                reason
            );
        }
        d => panic!("Expected deny on session limit, got {:?}", d),
    }
}

#[tokio::test]
async fn test_rate_limit_per_minute_cap() {
    let mut core = create_core_with_defaults();
    core.validate_session_tokens = false;
    core.set_policy(make_policy_with_rate_limit(None, Some(3)));

    for i in 0..3u32 {
        let ev = tool_event_id("ping", &i.to_string(), "sess");
        if let SecurityDecision::Deny { .. } = core.evaluate(ev).await {
            panic!("call {} should be allowed", i);
        }
    }
    let ev = tool_event_id("ping", "4", "sess");
    match core.evaluate(ev).await {
        SecurityDecision::Deny { reason, .. } => {
            assert!(
                reason.contains("Per-minute call limit exceeded"),
                "got: {}",
                reason
            );
        }
        d => panic!("Expected per-minute deny, got {:?}", d),
    }
}

// ─── Replay nonce ───────────────────────────────────────────────────────────

fn make_policy_with_replay_window(window_secs: u64) -> PolicyDefinition {
    let mut static_rules = HashMap::new();
    static_rules.insert("ping".to_string(), "ALLOW".to_string());
    PolicyDefinition {
        id: "replay-test".to_string(),
        customer_id: "test".to_string(),
        name: "Replay Test".to_string(),
        description: None,
        schema_version: None,
        version: 1,
        static_rules,
        taint_rules: vec![],
        created_at: None,
        resource_rules: vec![],
        protect_lethal_trifecta: false,
        tool_classes: Default::default(),
        rate_limit: None,
        replay_window_secs: window_secs,
        pin_mode: None,
    }
}

#[tokio::test]
async fn test_replay_nonce_blocks_duplicate_id() {
    let mut core = create_core_with_defaults();
    core.validate_session_tokens = false;
    core.set_policy(make_policy_with_replay_window(300));

    let ev1 = tool_event_id("ping", "req-42", "sess");
    if let SecurityDecision::Deny { .. } = core.evaluate(ev1).await {
        panic!("first request should be allowed");
    }
    // Same request ID should be denied.
    let ev2 = tool_event_id("ping", "req-42", "sess");
    match core.evaluate(ev2).await {
        SecurityDecision::Deny { reason, .. } => {
            assert!(reason.contains("Replayed request id"), "got: {}", reason);
        }
        d => panic!("Expected replay deny, got {:?}", d),
    }
}

#[tokio::test]
async fn test_replay_nonce_different_ids_allowed() {
    let mut core = create_core_with_defaults();
    core.validate_session_tokens = false;
    core.set_policy(make_policy_with_replay_window(300));

    for id in ["req-1", "req-2", "req-3"] {
        let ev = tool_event_id("ping", id, "sess");
        if let SecurityDecision::Deny { reason, .. } = core.evaluate(ev).await {
            panic!("unique id {} denied unexpectedly: {}", id, reason);
        }
    }
}

#[tokio::test]
async fn test_replay_window_zero_disables_protection() {
    let mut core = create_core_with_defaults();
    core.validate_session_tokens = false;
    core.set_policy(make_policy_with_replay_window(0));

    // Same ID twice should both be allowed when window is 0.
    for _ in 0..2 {
        let ev = tool_event_id("ping", "same-id", "sess");
        match core.evaluate(ev).await {
            SecurityDecision::Deny { reason, .. } if reason.contains("Replayed") => {
                panic!("replay window=0 should not block")
            }
            _ => {}
        }
    }
}

// ─── Resource path arg enforcement ──────────────────────────────────────────

fn make_policy_with_resource_rules() -> PolicyDefinition {
    let mut static_rules = HashMap::new();
    static_rules.insert("read_file".to_string(), "ALLOW".to_string());
    PolicyDefinition {
        id: "path-test".to_string(),
        customer_id: "test".to_string(),
        name: "Path Test".to_string(),
        description: None,
        schema_version: None,
        version: 1,
        static_rules,
        taint_rules: vec![],
        created_at: None,
        resource_rules: vec![
            ResourceRule {
                uri_pattern: "/etc/*".to_string(),
                action: "BLOCK".to_string(),
                exceptions: None,
                taints_to_add: None,
            },
            ResourceRule {
                uri_pattern: "*/.env".to_string(),
                action: "BLOCK".to_string(),
                exceptions: None,
                taints_to_add: None,
            },
            ResourceRule {
                uri_pattern: "/home/*".to_string(),
                action: "ALLOW".to_string(),
                exceptions: None,
                taints_to_add: Some(vec!["ACCESS_PRIVATE".to_string()]),
            },
        ],
        protect_lethal_trifecta: false,
        tool_classes: Default::default(),
        rate_limit: None,
        replay_window_secs: 0,
        pin_mode: None,
    }
}

fn tool_event_with_path(tool: &str, path: &str) -> SecurityEvent {
    SecurityEvent::ToolRequest {
        request_id: serde_json::Value::String("r".to_string()),
        tool_name: TaintedString::new(tool.to_string()),
        arguments: Tainted::new(serde_json::json!({"path": path}), vec![]),
        session_token: None,
    }
}

#[tokio::test]
async fn test_resource_path_arg_blocks_etc() {
    let mut core = create_core_with_defaults();
    core.validate_session_tokens = false;
    core.set_policy(make_policy_with_resource_rules());

    let ev = tool_event_with_path("read_file", "/etc/passwd");
    match core.evaluate(ev).await {
        SecurityDecision::Deny { reason, .. } => {
            assert!(
                reason.contains("blocked by resource rule"),
                "got: {}",
                reason
            );
        }
        d => panic!("Expected deny for /etc/passwd, got {:?}", d),
    }
}

#[tokio::test]
async fn test_resource_path_arg_blocks_dotenv() {
    let mut core = create_core_with_defaults();
    core.validate_session_tokens = false;
    core.set_policy(make_policy_with_resource_rules());

    let ev = tool_event_with_path("read_file", "/home/user/project/.env");
    match core.evaluate(ev).await {
        SecurityDecision::Deny { reason, .. } => {
            assert!(
                reason.contains("blocked by resource rule"),
                "got: {}",
                reason
            );
        }
        d => panic!("Expected deny for .env, got {:?}", d),
    }
}

#[tokio::test]
async fn test_resource_path_arg_strips_file_uri_prefix() {
    let mut core = create_core_with_defaults();
    core.validate_session_tokens = false;
    core.set_policy(make_policy_with_resource_rules());

    let ev = tool_event_with_path("read_file", "file:///etc/shadow");
    match core.evaluate(ev).await {
        SecurityDecision::Deny { reason, .. } => {
            assert!(
                reason.contains("blocked by resource rule"),
                "got: {}",
                reason
            );
        }
        d => panic!("Expected deny for file:///etc/shadow, got {:?}", d),
    }
}

#[tokio::test]
async fn test_resource_path_arg_allows_home() {
    let mut core = create_core_with_defaults();
    core.validate_session_tokens = false;
    core.set_policy(make_policy_with_resource_rules());

    let ev = tool_event_with_path("read_file", "/home/user/report.txt");
    if let SecurityDecision::Deny { reason, .. } = core.evaluate(ev).await {
        panic!(
            "Expected allow for /home/user/report.txt, got deny: {}",
            reason
        );
    }
}
