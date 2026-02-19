//! Integration tests for Security Core Policy Enforcement
//! Covers:
//! - Fail-Closed default behavior (No Policy)
//! - Lethal Trifecta protection
//! - Resource Taint tracking

use lilith_zero::config::{Config, SecurityLevel};
use lilith_zero::engine_core::crypto::CryptoSigner;
use lilith_zero::engine_core::events::{OutputTransform, SecurityDecision, SecurityEvent};
use lilith_zero::engine_core::models::{PolicyDefinition, PolicyRule, ResourceRule};
use lilith_zero::engine_core::security_core::SecurityCore;
use lilith_zero::engine_core::taint::Tainted;
use lilith_zero::engine_core::types::TaintedString;
use std::collections::HashMap;
use std::sync::Arc;

// --- Helpers ---

fn create_core_with_defaults() -> SecurityCore {
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
        pattern: None,
        exceptions: None,
    })
    .collect();

    PolicyDefinition {
        id: "test-policy".to_string(),
        customer_id: "test-customer".to_string(),
        name: "Test Policy".to_string(),
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
    core.evaluate(create_security_event("read_db", &token))
        .await;

    // 2. Access Untrusted Source
    core.evaluate(create_security_event("fetch_url", &token))
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
    core.evaluate(create_security_event("read_db", &token))
        .await;
    core.evaluate(create_security_event("fetch_url", &token))
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
    core.evaluate(res_event).await;

    // 2. Read Untrusted Resource
    let http_event = SecurityEvent::ResourceRequest {
        request_id: serde_json::Value::String("2".to_string()),
        uri: TaintedString::new("http://evil.com".to_string()),
        session_token: Some(token.clone()),
    };
    core.evaluate(http_event).await;

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

#[tokio::test]
async fn test_spotlighting_enabled() {
    let config = Config {
        security_level: SecurityLevel::BlockParams,
        ..Config::default()
    };
    // Spotlighting is enabled by default in SecurityLevel Config, but let's be explicit if possible.
    // Config struct doesn't have direct spotlight bool, it's inferred from level.
    // BlockParams -> Spotlighting ON.

    let signer = CryptoSigner::try_new().unwrap();
    let mut core = SecurityCore::new(Arc::new(config), signer, None).unwrap();
    core.set_policy(create_test_policy(false));
    let token = core.session_id.clone();

    // Allow rule triggers spotlighting
    let event = create_security_event("read_db", &token);
    let decision = core.evaluate(event).await;

    match decision {
        SecurityDecision::AllowWithTransforms {
            output_transforms, ..
        } => {
            assert!(output_transforms
                .iter()
                .any(|t| matches!(t, OutputTransform::Spotlight { .. })));
        }
        _ => panic!("FAIL: Expected Spotlighting, got {:?}", decision),
    }
}
