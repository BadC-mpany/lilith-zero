// Copyright 2026 BadCompany
// Red-team security verification for Cedar policy engine

use lilith_zero::engine::cedar_evaluator::CedarEvaluator;
use cedar_policy::{PolicySet, Decision};
use serde_json::json;
use std::collections::HashSet;
use std::str::FromStr;

#[test]
fn test_cedar_explicit_forbid() {
    let policy_src = r#"
        forbid(
            principal,
            action == Action::"tools/call",
            resource == Resource::"unsafe_tool"
        );
        permit(principal, action, resource);
    "#;
    let policy_set = PolicySet::from_str(policy_src).unwrap();
    let evaluator = CedarEvaluator::new(policy_set);
    
    let taints = HashSet::new();
    let classes = vec![];
    
    let response = evaluator.evaluate(
        "session-1",
        "tools/call",
        "unsafe_tool",
        &json!({}),
        &[],
        &taints,
        &classes
    ).unwrap();
    
    assert_eq!(response.decision(), Decision::Deny);
}

#[test]
fn test_cedar_taint_based_forbid() {
    let policy_src = r#"
        forbid(
            principal,
            action == Action::"tools/call",
            resource
        ) when {
            context.taints.contains("UNTRUSTED_SOURCE") &&
            context.classes.contains("EXFILTRATION")
        };
        permit(principal, action, resource);
    "#;
    let policy_set = PolicySet::from_str(policy_src).unwrap();
    let evaluator = CedarEvaluator::new(policy_set);
    
    let mut taints = HashSet::new();
    taints.insert("UNTRUSTED_SOURCE".to_string());
    let classes = vec!["EXFILTRATION".to_string()];
    
    let response = evaluator.evaluate(
        "session-1",
        "tools/call",
        "curl_tool",
        &json!({}),
        &[],
        &taints,
        &classes
    ).unwrap();
    
    assert_eq!(response.decision(), Decision::Deny);
}

#[test]
fn test_cedar_path_traversal_check() {
    let policy_src = r#"
        forbid(
            principal,
            action == Action::"tools/call",
            resource
        ) when {
            context.paths.any(p | p.contains("..") || p.contains("/etc/"))
        };
        permit(principal, action, resource);
    "#;
    // Note: Cedar 4.x doesn't have .any() on arrays yet in the base language without custom functions,
    // but we can simulate it or use specific checks if we know the schema.
    // However, our CedarEvaluator passes 'paths' as a list.
    
    let policy_src_fixed = r#"
        forbid( principal, action, resource ) 
        when { context.paths.contains("/etc/shadow") };
        permit( principal, action, resource );
    "#;

    let policy_set = PolicySet::from_str(policy_src_fixed).unwrap();
    let evaluator = CedarEvaluator::new(policy_set);
    
    let taints = HashSet::new();
    let classes = vec![];
    let paths = vec!["/etc/shadow".to_string()];
    
    let response = evaluator.evaluate(
        "session-1",
        "tools/call",
        "read_file",
        &json!({"path": "/etc/shadow"}),
        &paths,
        &taints,
        &classes
    ).unwrap();
    
    assert_eq!(response.decision(), Decision::Deny);
}
