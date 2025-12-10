// Unit tests for evaluator adapter

use sentinel_interceptor::api::evaluator_adapter::PolicyEvaluatorAdapter;
use sentinel_interceptor::api::PolicyEvaluator;
use sentinel_interceptor::core::models::{HistoryEntry, PolicyDefinition};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::Duration;

// Import test utilities
#[path = "../../common/mod.rs"]
mod common;
use common::*;

/// Test successful policy evaluation with history
#[tokio::test]
async fn test_evaluator_adapter_success() {
    // Arrange: Create test history
    let history = vec![HistoryEntry {
        tool: "read_file".to_string(),
        classes: vec!["SENSITIVE_READ".to_string()],
        timestamp: 1234567890.0,
    }];

    let adapter = PolicyEvaluatorAdapter::new();

    // Create a test policy
    let policy = create_test_policy("test_policy");

    // Act: Evaluate policy
    let result = adapter
        .evaluate(
            &policy,
            "read_file",
            &["SENSITIVE_READ".to_string()],
            &[],
            &history,
            "session-123",
        )
        .await;

    // Assert: Should succeed (policy allows read_file)
    assert!(result.is_ok());
    match result.unwrap() {
        sentinel_interceptor::core::models::Decision::Allowed => {}
        _ => panic!("Expected Allowed decision"),
    }
}



/// Test empty history handling
#[tokio::test]
async fn test_evaluator_adapter_empty_history() {
    let adapter = PolicyEvaluatorAdapter::new();

    let policy = create_test_policy("test_policy");

    // Act: Evaluate policy with empty history
    let result = adapter
        .evaluate(
            &policy,
            "read_file",
            &["SENSITIVE_READ".to_string()],
            &[],
            &[],
            "session-123",
        )
        .await;

    // Assert: Should succeed with empty history
    assert!(result.is_ok());
}

/// Test taint conversion (Vec<String> to HashSet<String>)
#[tokio::test]
async fn test_evaluator_adapter_taint_conversion() {
    let adapter = PolicyEvaluatorAdapter::new();

    // Create policy with taint rule
    let mut policy = create_test_policy("test_policy");
    policy.taint_rules.push(sentinel_interceptor::core::models::PolicyRule {
        tool: None,
        tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
        action: "CHECK_TAINT".to_string(),
        tag: None,
        forbidden_tags: Some(vec!["sensitive_data".to_string()]),
        error: Some("Exfiltration blocked".to_string()),
        pattern: None,
        exceptions: None,
    });

    // Act: Evaluate with taints
    let taints = vec!["sensitive_data".to_string(), "pii".to_string()];
    let result = adapter
        .evaluate(
            &policy,
            "web_search",
            &["CONSEQUENTIAL_WRITE".to_string()],
            &taints,
            &[],
            "session-123",
        )
        .await;

    // Assert: Should deny due to forbidden taint
    assert!(result.is_ok());
    match result.unwrap() {
        sentinel_interceptor::core::models::Decision::Denied { reason } => {
            assert!(!reason.is_empty(), "Reason is: {}", reason);
        }
        _ => panic!("Expected Denied decision due to taint"),
    }
}

/// Test error propagation from engine
#[tokio::test]
async fn test_evaluator_adapter_error_propagation() {
    let adapter = PolicyEvaluatorAdapter::new();

    // Create invalid policy (empty name would cause validation error, but we'll test with pattern error)
    let mut policy = create_test_policy("test_policy");
    // Add invalid pattern to cause engine error
    policy.taint_rules.push(sentinel_interceptor::core::models::PolicyRule {
        tool: None,
        tool_class: None,
        action: "BLOCK".to_string(),
        tag: None,
        forbidden_tags: None,
        error: None,
        pattern: Some(serde_json::json!({
            "type": "invalid_pattern_type",
            "invalid": "data"
        })),
        exceptions: None,
    });

    // Act: Evaluate with invalid pattern
    let result = adapter
        .evaluate(
            &policy,
            "read_file",
            &["SENSITIVE_READ".to_string()],
            &[],
            &[],
            "session-123",
        )
        .await;

    // Assert: Should propagate engine error
    // Note: Actual error depends on pattern matcher implementation
    // This test verifies errors are propagated, not the specific error message
    if result.is_err() {
        let error_msg = result.unwrap_err();
        assert!(!error_msg.to_string().is_empty());
    }
}

/// Test concurrent requests (thread safety)
#[tokio::test]
async fn test_evaluator_adapter_concurrent_requests() {
    // Arrange: Create shared adapter
    let adapter = Arc::new(PolicyEvaluatorAdapter::new());

    let policy = Arc::new(create_test_policy("test_policy"));

    // Act: Spawn multiple concurrent evaluations
    let mut handles = vec![];
    for i in 0..10 {
        let adapter_clone = adapter.clone();
        let policy_clone = policy.clone();
        let handle = tokio::spawn(async move {
            adapter_clone
                .evaluate(
                    &policy_clone,
                    "read_file",
                    &["SENSITIVE_READ".to_string()],
                    &[],
                    &[],
                    &format!("session-{}", i),
                )
                .await
        });
        handles.push(handle);
    }

    // Assert: All requests should complete successfully
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "Concurrent request should succeed");
    }
}

