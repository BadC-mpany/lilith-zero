// Static and dynamic rule evaluation
use crate::core::errors::InterceptorError;
use crate::core::models::{Decision, HistoryEntry, PolicyDefinition};
use crate::engine::pattern_matcher::PatternMatcher;
use serde_json::Value;
use std::collections::HashSet;

pub struct PolicyEvaluator;

impl PolicyEvaluator {
    pub async fn evaluate_with_args(
        policy: &PolicyDefinition,
        tool_name: &str,
        tool_classes: &[String],
        session_history: &[HistoryEntry],
        current_taints: &HashSet<String>,
        tool_args: &Value,
    ) -> Result<Decision, InterceptorError> {
        // 1. Static rules (ACL)
        let permission = policy.static_rules.get(tool_name).map(|s| s.as_str()).unwrap_or("DENY");
        
        if permission == "DENY" {
            return Ok(Decision::Denied {
                reason: format!("Tool '{}' is forbidden by static policy", tool_name),
            });
        }

        // 2. Dynamic taint rules
        let mut taints_to_add = Vec::new();
        let mut taints_to_remove = Vec::new();

        for rule in &policy.taint_rules {
            if let Some(pattern) = &rule.pattern {
                let pattern_matched = PatternMatcher::evaluate_pattern_with_args(
                    pattern,
                    session_history,
                    tool_name,
                    tool_classes,
                    current_taints,
                    tool_args,
                )
                .await?;

                if pattern_matched {
                    match rule.action.as_str() {
                        "BLOCK" => {
                            let error_msg = rule.error.clone().unwrap_or_else(|| "Pattern block".to_string());
                            return Ok(Decision::Denied { reason: error_msg });
                        }
                        _ => {}
                    }
                }
            } else if rule.matches_tool(tool_name, tool_classes) {
                match rule.action.as_str() {
                    "CHECK_TAINT" => {
                        if let Some(ref forbidden_tags) = rule.forbidden_tags {
                            for forbidden_tag in forbidden_tags {
                                if current_taints.contains(forbidden_tag) {
                                    // Check exceptions
                                    if let Some(ref exceptions) = rule.exceptions {
                                        if Self::check_exceptions(exceptions, session_history, tool_name, tool_classes, current_taints, tool_args).await? {
                                            continue;
                                        }
                                    }
                                    let error_msg = rule.error.clone().unwrap_or_else(|| "Forbidden taint detected".to_string());
                                    return Ok(Decision::Denied { reason: error_msg });
                                }
                            }
                        }
                    }
                    "ADD_TAINT" => {
                        if let Some(ref tag) = rule.tag { taints_to_add.push(tag.clone()); }
                    }
                    "REMOVE_TAINT" => {
                        if let Some(ref tag) = rule.tag { taints_to_remove.push(tag.clone()); }
                    }
                    "BLOCK" => {
                         let error_msg = rule.error.clone().unwrap_or_else(|| "Tool block".to_string());
                         return Ok(Decision::Denied { reason: error_msg });
                    }
                    _ => {}
                }
            }
        }

        if taints_to_add.is_empty() && taints_to_remove.is_empty() {
            Ok(Decision::Allowed)
        } else {
            Ok(Decision::AllowedWithSideEffects { taints_to_add, taints_to_remove })
        }
    }

    async fn check_exceptions(
        exceptions: &[crate::core::models::RuleException],
        session_history: &[HistoryEntry],
        tool_name: &str,
        tool_classes: &[String],
        current_taints: &HashSet<String>,
        tool_args: &Value,
    ) -> Result<bool, InterceptorError> {
        for exception in exceptions {
            if PatternMatcher::evaluate_condition_with_args(&exception.condition, session_history, tool_name, tool_classes, current_taints, tool_args).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
