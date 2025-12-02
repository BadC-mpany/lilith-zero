// Static and dynamic rule evaluation - Core policy enforcement logic

use crate::core::errors::InterceptorError;
use crate::core::models::{Decision, HistoryEntry, PolicyDefinition};
use crate::engine::pattern_matcher::PatternMatcher;
use std::collections::HashSet;

/// Policy evaluator - evaluates static and dynamic rules
pub struct PolicyEvaluator;

impl PolicyEvaluator {
    /// Evaluate policy for a tool call
    /// 
    /// Evaluation order (matches Python implementation):
    /// 1. Static rules (ALLOW/DENY) - O(1) HashMap lookup
    /// 2. Dynamic taint rules:
    ///    a. Pattern-based rules (sequence, logic)
    ///    b. Simple taint rules (ADD_TAINT, CHECK_TAINT, REMOVE_TAINT)
    /// 3. Aggregate decision with side effects
    pub fn evaluate(
        policy: &PolicyDefinition,
        tool_name: &str,
        tool_classes: &[String],
        session_history: &[HistoryEntry],
        current_taints: &HashSet<String>,
    ) -> Result<Decision, InterceptorError> {
        // Step 1: Static rule check (ACL)
        let permission = policy.static_rules.get(tool_name).map(|s| s.as_str()).unwrap_or("DENY");
        
        if permission == "DENY" {
            return Ok(Decision::Denied {
                reason: format!("Tool '{}' is forbidden by static policy", tool_name),
            });
        }

        // Step 2: Dynamic taint rule evaluation
        let mut taints_to_add = Vec::new();
        let mut taints_to_remove = Vec::new();

        for rule in &policy.taint_rules {
            // Check pattern-based rules first
            if let Some(pattern) = &rule.pattern {
                let pattern_matched = PatternMatcher::evaluate_pattern(
                    pattern,
                    session_history,
                    tool_name,
                    tool_classes,
                    current_taints,
                )?;

                if pattern_matched {
                    match rule.action.as_str() {
                        "BLOCK" | "BLOCK_CURRENT" | "BLOCK_SECOND" => {
                            let error_msg = rule.error.clone()
                                .unwrap_or_else(|| "Pattern-based security block".to_string());
                            return Ok(Decision::Denied { reason: error_msg });
                        }
                        _ => {
                            // Pattern matched but action is not a block - continue
                        }
                    }
                }
            } else {
                // Simple taint rules (non-pattern)
                if rule.matches_tool(tool_name, tool_classes) {
                    match rule.action.as_str() {
                        "CHECK_TAINT" => {
                            if let Some(ref forbidden_tags) = rule.forbidden_tags {
                                // Check if session has any forbidden taint
                                for forbidden_tag in forbidden_tags {
                                    if current_taints.contains(forbidden_tag) {
                                        let error_msg = rule.error.clone()
                                            .unwrap_or_else(|| "Security block: forbidden taint detected".to_string());
                                        return Ok(Decision::Denied { reason: error_msg });
                                    }
                                }
                            }
                        }
                        "ADD_TAINT" => {
                            if let Some(ref tag) = rule.tag {
                                taints_to_add.push(tag.clone());
                            }
                        }
                        "REMOVE_TAINT" => {
                            // Note: Redis is append-only. REMOVE_TAINT is tracked for
                            // future implementation (e.g., via separate sanitization log)
                            // For now, we record it in decision but don't actively remove
                            if let Some(ref tag) = rule.tag {
                                taints_to_remove.push(tag.clone());
                            }
                        }
                        _ => {
                            // Unknown action - log warning but continue
                        }
                    }
                }
            }
        }

        // Step 3: Return decision with side effects
        if taints_to_add.is_empty() && taints_to_remove.is_empty() {
            Ok(Decision::Allowed)
        } else {
            Ok(Decision::AllowedWithSideEffects {
                taints_to_add,
                taints_to_remove,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::{PolicyDefinition, PolicyRule};
    use std::collections::HashMap;

    #[test]
    fn test_static_rule_deny() {
        let mut static_rules = HashMap::new();
        static_rules.insert("read_file".to_string(), "ALLOW".to_string());
        static_rules.insert("delete_db".to_string(), "DENY".to_string());

        let policy = PolicyDefinition {
            name: "test_policy".to_string(),
            static_rules,
            taint_rules: vec![],
        };

        let result = PolicyEvaluator::evaluate(
            &policy,
            "delete_db",
            &[],
            &[],
            &HashSet::new(),
        ).unwrap();

        match result {
            Decision::Denied { reason } => {
                assert!(reason.contains("delete_db"));
            }
            _ => panic!("Expected Denied decision"),
        }
    }

    #[test]
    fn test_static_rule_allow() {
        let mut static_rules = HashMap::new();
        static_rules.insert("read_file".to_string(), "ALLOW".to_string());

        let policy = PolicyDefinition {
            name: "test_policy".to_string(),
            static_rules,
            taint_rules: vec![],
        };

        let result = PolicyEvaluator::evaluate(
            &policy,
            "read_file",
            &[],
            &[],
            &HashSet::new(),
        ).unwrap();

        assert!(matches!(result, Decision::Allowed));
    }

    #[test]
    fn test_add_taint_rule() {
        let mut static_rules = HashMap::new();
        static_rules.insert("read_file".to_string(), "ALLOW".to_string());

        let taint_rule = PolicyRule {
            tool: Some("read_file".to_string()),
            tool_class: None,
            action: "ADD_TAINT".to_string(),
            tag: Some("sensitive_data".to_string()),
            forbidden_tags: None,
            error: None,
            pattern: None,
        };

        let policy = PolicyDefinition {
            name: "test_policy".to_string(),
            static_rules,
            taint_rules: vec![taint_rule],
        };

        let result = PolicyEvaluator::evaluate(
            &policy,
            "read_file",
            &[],
            &[],
            &HashSet::new(),
        ).unwrap();

        match result {
            Decision::AllowedWithSideEffects { taints_to_add, .. } => {
                assert!(taints_to_add.contains(&"sensitive_data".to_string()));
            }
            _ => panic!("Expected AllowedWithSideEffects decision"),
        }
    }

    #[test]
    fn test_check_taint_rule() {
        let mut static_rules = HashMap::new();
        static_rules.insert("web_search".to_string(), "ALLOW".to_string());

        let taint_rule = PolicyRule {
            tool: None,
            tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
            action: "CHECK_TAINT".to_string(),
            tag: None,
            forbidden_tags: Some(vec!["sensitive_data".to_string()]),
            error: Some("Exfiltration blocked".to_string()),
            pattern: None,
        };

        let policy = PolicyDefinition {
            name: "test_policy".to_string(),
            static_rules,
            taint_rules: vec![taint_rule],
        };

        let mut current_taints = HashSet::new();
        current_taints.insert("sensitive_data".to_string());

        let result = PolicyEvaluator::evaluate(
            &policy,
            "web_search",
            &["CONSEQUENTIAL_WRITE".to_string()],
            &[],
            &current_taints,
        ).unwrap();

        match result {
            Decision::Denied { reason } => {
                assert!(reason.contains("Exfiltration blocked"));
            }
            _ => panic!("Expected Denied decision"),
        }
    }
}
