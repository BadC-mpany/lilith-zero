// Unit tests for wildcard argument matching

use sentinel_interceptor::engine::pattern_matcher::PatternMatcher;
use serde_json::json;
use std::collections::HashSet;

#[tokio::test]
async fn test_wildcard_prefix() {
    let pattern = json!({
        "type": "logic",
        "condition": {
            "tool_args_match": {"destination": "internal_*"}
        }
    });

    let current_taints = HashSet::new();
    
    // Should match
    let result = PatternMatcher::evaluate_condition_with_args(
        &pattern.get("condition").unwrap(),
        &[],
        "send_email",
        &[],
        &current_taints,
        &json!({"destination": "internal_team"}),
    )
    .await
    .unwrap();
    assert!(result);

    // Should not match
    let result = PatternMatcher::evaluate_condition_with_args(
        &pattern.get("condition").unwrap(),
        &[],
        "send_email",
        &[],
        &current_taints,
        &json!({"destination": "external_team"}),
    )
    .await
    .unwrap();
    assert!(!result);
}

#[tokio::test]
async fn test_wildcard_suffix() {
    let pattern = json!({
        "tool_args_match": {"email": "*@company.com"}
    });

    let current_taints = HashSet::new();
    
    // Should match
    let result = PatternMatcher::evaluate_condition_with_args(
        &pattern,
        &[],
        "send_email",
        &[],
        &current_taints,
        &json!({"email": "user@company.com"}),
    )
    .await
    .unwrap();
    assert!(result);

    // Should not match
    let result = PatternMatcher::evaluate_condition_with_args(
        &pattern,
        &[],
        "send_email",
        &[],
        &current_taints,
        &json!({"email": "user@external.com"}),
    )
    .await
    .unwrap();
    assert!(!result);
}

#[tokio::test]
async fn test_wildcard_middle() {
    let pattern = json!({
        "tool_args_match": {"path": "/safe/*/data.csv"}
    });

    let current_taints = HashSet::new();
    
    // Should match
    let result = PatternMatcher::evaluate_condition_with_args(
        &pattern,
        &[],
        "read_file",
        &[],
        &current_taints,
        &json!({"path": "/safe/public/data.csv"}),
    )
    .await
    .unwrap();
    assert!(result);

    let result = PatternMatcher::evaluate_condition_with_args(
        &pattern,
        &[],
        "read_file",
        &[],
        &current_taints,
        &json!({"path": "/safe/internal/data.csv"}),
    )
    .await
    .unwrap();
    assert!(result);

    // Should not match
    let result = PatternMatcher::evaluate_condition_with_args(
        &pattern,
        &[],
        "read_file",
        &[],
        &current_taints,
        &json!({"path": "/unsafe/public/data.csv"}),
    )
    .await
    .unwrap();
    assert!(!result);
}

#[tokio::test]
async fn test_exact_match_no_wildcard() {
    let pattern = json!({
        "tool_args_match": {"priority": "low"}
    });

    let current_taints = HashSet::new();
    
    // Should match
    let result = PatternMatcher::evaluate_condition_with_args(
        &pattern,
        &[],
        "send_email",
        &[],
        &current_taints,
        &json!({"priority": "low"}),
    )
    .await
    .unwrap();
    assert!(result);

    // Should not match
    let result = PatternMatcher::evaluate_condition_with_args(
        &pattern,
        &[],
        "send_email",
        &[],
        &current_taints,
        &json!({"priority": "high"}),
    )
    .await
    .unwrap();
    assert!(!result);
}
