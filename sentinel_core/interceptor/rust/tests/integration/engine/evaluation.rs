// Real integration tests for policy evaluation

use sentinel_interceptor::api::evaluator_adapter::PolicyEvaluatorAdapter;
use sentinel_interceptor::api::PolicyEvaluator;
use sentinel_interceptor::core::models::{Decision, HistoryEntry, PolicyRule};
use std::collections::HashMap;
use std::sync::Arc;

use super::super::common::*;

#[tokio::test]
async fn test_policy_evaluation_static_allow() {
    let redis_store = Arc::new(MockRedisStore::default());
    let adapter = PolicyEvaluatorAdapter::new(redis_store);
    
    let mut static_rules = HashMap::new();
    static_rules.insert("read_file".to_string(), "ALLOW".to_string());
    
    let policy = sentinel_interceptor::core::models::PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![],
    };
    
    let decision = adapter.evaluate(
        &policy,
        "read_file",
        &["FILE_OPERATION".to_string()],
        &[],
        "session-123",
    ).await.unwrap();
    
    assert!(matches!(decision, Decision::Allowed { .. }));
}

#[tokio::test]
async fn test_policy_evaluation_static_deny() {
    let redis_store = Arc::new(MockRedisStore::default());
    let adapter = PolicyEvaluatorAdapter::new(redis_store);
    
    let mut static_rules = HashMap::new();
    static_rules.insert("write_file".to_string(), "DENY".to_string());
    
    let policy = sentinel_interceptor::core::models::PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![],
    };
    
    let decision = adapter.evaluate(
        &policy,
        "write_file",
        &["FILE_OPERATION".to_string()],
        &[],
        "session-123",
    ).await.unwrap();
    
    assert!(matches!(decision, Decision::Denied { .. }));
}

#[tokio::test]
async fn test_policy_evaluation_taint_rule_blocks() {
    let mut redis_store = MockRedisStore::default();
    redis_store.taints.insert(
        "session-123".to_string(),
        vec!["SENSITIVE_DATA".to_string()],
    );
    let redis_store = Arc::new(redis_store);
    let adapter = PolicyEvaluatorAdapter::new(redis_store);
    
    let static_rules = HashMap::new();
    let taint_rules = vec![PolicyRule {
        condition: "SENSITIVE_DATA in session_taints".to_string(),
        action: "DENY".to_string(),
        tool_pattern: "*".to_string(),
    }];
    
    let policy = sentinel_interceptor::core::models::PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules,
    };
    
    let decision = adapter.evaluate(
        &policy,
        "read_file",
        &["FILE_OPERATION".to_string()],
        &["SENSITIVE_DATA".to_string()],
        "session-123",
    ).await.unwrap();
    
    assert!(matches!(decision, Decision::Denied { .. }));
}

#[tokio::test]
async fn test_policy_evaluation_history_based_rule() {
    let mut redis_store = MockRedisStore::default();
    redis_store.history.insert(
        "session-123".to_string(),
        vec![
            HistoryEntry {
                tool: "read_file".to_string(),
                classes: vec!["FILE_OPERATION".to_string()],
            },
        ],
    );
    let redis_store = Arc::new(redis_store);
    let adapter = PolicyEvaluatorAdapter::new(redis_store);
    
    let static_rules = HashMap::new();
    let taint_rules = vec![PolicyRule {
        condition: "len(session_history) > 0".to_string(),
        action: "ALLOW".to_string(),
        tool_pattern: "read_file".to_string(),
    }];
    
    let policy = sentinel_interceptor::core::models::PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules,
    };
    
    let decision = adapter.evaluate(
        &policy,
        "read_file",
        &["FILE_OPERATION".to_string()],
        &[],
        "session-123", // Adapter will fetch history from Redis
    ).await.unwrap();
    
    // Should allow based on history
    assert!(matches!(decision, Decision::Allowed { .. }));
}

#[tokio::test]
async fn test_policy_evaluation_redis_failure_failsafe() {
    let mut redis_store = MockRedisStore::default();
    redis_store.get_history_should_fail = true;
    let redis_store = Arc::new(redis_store);
    let adapter = PolicyEvaluatorAdapter::new(redis_store);
    
    let static_rules = HashMap::new();
    let taint_rules = vec![PolicyRule {
        condition: "SENSITIVE_DATA in session_taints".to_string(),
        action: "DENY".to_string(),
        tool_pattern: "*".to_string(),
    }];
    
    let policy = sentinel_interceptor::core::models::PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules,
    };
    
    // Should proceed with empty history (fail-safe) when Redis fails
    let decision = adapter.evaluate(
        &policy,
        "read_file",
        &["FILE_OPERATION".to_string()],
        &[], // Empty taints (no SENSITIVE_DATA)
        "session-123", // Adapter will try to fetch history, fail, and use empty
    ).await.unwrap();
    
    // Should allow (no taints to block, empty history)
    assert!(matches!(decision, Decision::Allowed { .. }));
}

