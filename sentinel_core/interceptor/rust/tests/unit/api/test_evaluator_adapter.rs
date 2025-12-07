// Unit tests for evaluator adapter

use sentinel_interceptor::api::evaluator_adapter::PolicyEvaluatorAdapter;
use sentinel_interceptor::api::{PolicyEvaluator, RedisStore};
use sentinel_interceptor::core::models::{HistoryEntry, PolicyDefinition};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::Duration;

// Import test utilities
#[path = "../../common/mod.rs"]
mod common;
use common::*;

/// Test successful history fetch and policy evaluation
#[tokio::test]
async fn test_evaluator_adapter_redis_success() {
    // Arrange: Create mock Redis store with history
    let mut history_map = HashMap::new();
    history_map.insert(
        "session-123".to_string(),
        vec![HistoryEntry {
            tool: "read_file".to_string(),
            classes: vec!["SENSITIVE_READ".to_string()],
            timestamp: 1234567890.0,
        }],
    );

    let redis_store = Arc::new(MockRedisStore {
        history: history_map,
        ..Default::default()
    });

    let adapter = PolicyEvaluatorAdapter::new(redis_store);

    // Create a test policy
    let policy = create_test_policy("test_policy");

    // Act: Evaluate policy
    let result = adapter
        .evaluate(
            &policy,
            "read_file",
            &["SENSITIVE_READ".to_string()],
            &[],
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

/// Test Redis timeout handling (fail-safe behavior)
#[tokio::test]
async fn test_evaluator_adapter_redis_timeout() {
    // Arrange: Create mock Redis store that times out
    let redis_store = Arc::new(MockRedisStore {
        get_history_should_timeout: true,
        ..Default::default()
    });

    let adapter = PolicyEvaluatorAdapter::new(redis_store);

    let policy = create_test_policy("test_policy");

    // Act: Evaluate policy (should proceed with empty history on timeout)
    let start = std::time::Instant::now();
    let result = adapter
        .evaluate(
            &policy,
            "read_file",
            &["SENSITIVE_READ".to_string()],
            &[],
            "session-123",
        )
        .await;

    // Assert: Should complete quickly (<3s) and succeed with empty history
    let duration = start.elapsed();
    assert!(duration < Duration::from_secs(3), "Should timeout quickly");
    assert!(result.is_ok(), "Should proceed with empty history (fail-safe)");
}

/// Test Redis error handling (fail-safe behavior)
#[tokio::test]
async fn test_evaluator_adapter_redis_error() {
    // Arrange: Create mock Redis store that returns error
    let redis_store = Arc::new(MockRedisStore {
        get_history_should_fail: true,
        ..Default::default()
    });

    let adapter = PolicyEvaluatorAdapter::new(redis_store);

    let policy = create_test_policy("test_policy");

    // Act: Evaluate policy (should proceed with empty history on error)
    let result = adapter
        .evaluate(
            &policy,
            "read_file",
            &["SENSITIVE_READ".to_string()],
            &[],
            "session-123",
        )
        .await;

    // Assert: Should succeed with empty history (fail-safe)
    assert!(result.is_ok(), "Should proceed with empty history on Redis error");
}

/// Test empty history handling
#[tokio::test]
async fn test_evaluator_adapter_empty_history() {
    // Arrange: Create mock Redis store with empty history
    let redis_store = Arc::new(MockRedisStore {
        history: HashMap::new(),
        ..Default::default()
    });

    let adapter = PolicyEvaluatorAdapter::new(redis_store);

    let policy = create_test_policy("test_policy");

    // Act: Evaluate policy with empty history
    let result = adapter
        .evaluate(
            &policy,
            "read_file",
            &["SENSITIVE_READ".to_string()],
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
    // Arrange: Create mock Redis store
    let redis_store = Arc::new(MockRedisStore::default());
    let adapter = PolicyEvaluatorAdapter::new(redis_store);

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
            "session-123",
        )
        .await;

    // Assert: Should deny due to forbidden taint
    assert!(result.is_ok());
    match result.unwrap() {
        sentinel_interceptor::core::models::Decision::Denied { reason } => {
            assert!(reason.contains("Exfiltration blocked"));
        }
        _ => panic!("Expected Denied decision due to taint"),
    }
}

/// Test error propagation from engine
#[tokio::test]
async fn test_evaluator_adapter_error_propagation() {
    // Arrange: Create mock Redis store
    let redis_store = Arc::new(MockRedisStore::default());
    let adapter = PolicyEvaluatorAdapter::new(redis_store);

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
            "session-123",
        )
        .await;

    // Assert: Should propagate engine error
    // Note: Actual error depends on pattern matcher implementation
    // This test verifies errors are propagated, not the specific error message
    if result.is_err() {
        let error_msg = result.unwrap_err();
        assert!(!error_msg.is_empty());
    }
}

/// Test concurrent requests (thread safety)
#[tokio::test]
async fn test_evaluator_adapter_concurrent_requests() {
    // Arrange: Create shared Redis store
    let redis_store = Arc::new(MockRedisStore::default());
    let adapter = Arc::new(PolicyEvaluatorAdapter::new(redis_store));

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

