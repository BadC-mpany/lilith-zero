// Copyright 2026 BadCompany
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Policy evaluation engine.
//!
//! This module implements the `PolicyEvaluator` which applies static and dynamic
//! rules to tool calls based on the active policy and session context.

// Static and dynamic rule evaluation
use crate::engine::pattern_matcher::PatternMatcher;
use crate::engine_core::errors::InterceptorError;
use crate::engine_core::models::{Decision, HistoryEntry, PolicyDefinition};
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
        let permission = policy
            .static_rules
            .get(tool_name)
            .map(|s| s.as_str())
            .unwrap_or("DENY");

        if permission == "DENY" {
            return Ok(Decision::Denied {
                reason: format!("Tool '{}' is forbidden by static policy", tool_name),
            });
        }

        // 2. Dynamic taint rules
        let mut taints_to_add = Vec::new();
        let mut taints_to_remove = Vec::new();

        // collect taints that will be added
        for rule in &policy.taint_rules {
            if rule.matches_tool(tool_name, tool_classes) && rule.action == "ADD_TAINT" {
                if let Some(ref tag) = rule.tag {
                    taints_to_add.push(tag.clone());
                }
            }
        }

        // Augment tool_classes with taints about to be added
        // This allows tools that add "EXFILTRATION" taint to match rules with toolClass: "EXFILTRATION"
        let mut augmented_classes = tool_classes.to_vec();
        augmented_classes.extend(taints_to_add.clone());

        for rule in &policy.taint_rules {
            if let Some(pattern) = &rule.pattern {
                let pattern_matched = PatternMatcher::evaluate_pattern_with_args(
                    pattern,
                    session_history,
                    tool_name,
                    &augmented_classes,
                    current_taints,
                    tool_args,
                )
                .await?;

                if pattern_matched && rule.action == "BLOCK" {
                    let error_msg = rule
                        .error
                        .clone()
                        .unwrap_or_else(|| "Pattern block".to_string());
                    return Ok(Decision::Denied { reason: error_msg });
                }
            } else if rule.matches_tool(tool_name, &augmented_classes) {
                match rule.action.as_str() {
                    "CHECK_TAINT" => {
                        // Check forbidden tags (OR logic - block if ANY present)
                        if let Some(ref forbidden_tags) = rule.forbidden_tags {
                            for forbidden_tag in forbidden_tags {
                                if current_taints.contains(forbidden_tag) {
                                    // Check exceptions
                                    if let Some(ref exceptions) = rule.exceptions {
                                        if Self::check_exceptions(
                                            exceptions,
                                            session_history,
                                            tool_name,
                                            tool_classes,
                                            current_taints,
                                            tool_args,
                                        )
                                        .await?
                                        {
                                            continue;
                                        }
                                    }
                                    let error_msg = rule
                                        .error
                                        .clone()
                                        .unwrap_or_else(|| "Forbidden taint detected".to_string());
                                    return Ok(Decision::Denied { reason: error_msg });
                                }
                            }
                        }

                        // Check required tags (AND logic - block if ALL present)
                        if let Some(ref required_tags) = rule.required_taints {
                            let all_present =
                                required_tags.iter().all(|tag| current_taints.contains(tag));

                            if all_present {
                                // Check exceptions
                                if let Some(ref exceptions) = rule.exceptions {
                                    if !Self::check_exceptions(
                                        exceptions,
                                        session_history,
                                        tool_name,
                                        tool_classes,
                                        current_taints,
                                        tool_args,
                                    )
                                    .await?
                                    {
                                        let error_msg = rule.error.clone().unwrap_or_else(|| {
                                            "Required taints detected".to_string()
                                        });
                                        return Ok(Decision::Denied { reason: error_msg });
                                    }
                                } else {
                                    let error_msg = rule
                                        .error
                                        .clone()
                                        .unwrap_or_else(|| "Required taints detected".to_string());
                                    return Ok(Decision::Denied { reason: error_msg });
                                }
                            }
                        }
                    }
                    "REMOVE_TAINT" => {
                        if let Some(ref tag) = rule.tag {
                            taints_to_remove.push(tag.clone());
                        }
                    }
                    "BLOCK" => {
                        if let Some(ref exceptions) = rule.exceptions {
                            if Self::check_exceptions(
                                exceptions,
                                session_history,
                                tool_name,
                                tool_classes,
                                current_taints,
                                tool_args,
                            )
                            .await?
                            {
                                continue;
                            }
                        }
                        let error_msg = rule
                            .error
                            .clone()
                            .unwrap_or_else(|| "Tool block".to_string());
                        return Ok(Decision::Denied { reason: error_msg });
                    }
                    _ => {}
                }
            }
        }

        if taints_to_add.is_empty() && taints_to_remove.is_empty() {
            Ok(Decision::Allowed)
        } else {
            Ok(Decision::AllowedWithSideEffects {
                taints_to_add,
                taints_to_remove,
            })
        }
    }

    async fn check_exceptions(
        exceptions: &[crate::engine_core::models::RuleException],
        session_history: &[HistoryEntry],
        tool_name: &str,
        tool_classes: &[String],
        current_taints: &HashSet<String>,
        tool_args: &Value,
    ) -> Result<bool, InterceptorError> {
        for exception in exceptions {
            if PatternMatcher::evaluate_condition_with_args(
                &exception.condition,
                session_history,
                tool_name,
                tool_classes,
                current_taints,
                tool_args,
                0, // Initial depth
            )? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
