// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::engine::pattern_matcher::PatternMatcher;
use crate::engine_core::errors::InterceptorError;
use crate::engine_core::models::{Decision, HistoryEntry, PolicyDefinition};
use serde_json::Value;
use std::collections::HashSet;

/// Evaluates a tool call against a [`PolicyDefinition`] and produces a [`Decision`].
pub struct PolicyEvaluator;

impl PolicyEvaluator {
    /// Evaluate `tool_name` (with `tool_classes`) against `policy`.
    ///
    /// Applies static rules first, then taint rules in order.  Returns
    /// [`Decision::Denied`] on the first matching block rule, or [`Decision::Allowed`] /
    /// [`Decision::AllowedWithSideEffects`] if all rules pass.
    pub async fn evaluate_with_args(
        policy: &PolicyDefinition,
        tool_name: &str,
        tool_classes: &[String],
        session_history: &[HistoryEntry],
        current_taints: &HashSet<String>,
        tool_args: &Value,
    ) -> Result<Decision, InterceptorError> {
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

        // Resource rule check on tool argument paths (path traversal / workspace boundary).
        if let Some(denied) = Self::evaluate_path_args(&policy.resource_rules, tool_args) {
            return Ok(denied);
        }

        let mut taints_to_add = Vec::new();
        let mut taints_to_remove = Vec::new();

        for rule in &policy.taint_rules {
            if rule.matches_tool(tool_name, tool_classes) && rule.action == "ADD_TAINT" {
                if let Some(ref tag) = rule.tag {
                    taints_to_add.push(tag.clone());
                }
            }
        }

        let mut augmented_classes = tool_classes.to_vec();
        augmented_classes.extend(taints_to_add.clone());

        for rule in &policy.taint_rules {
            if let Some(pattern) = &rule.pattern {
                if !rule.matches_tool(tool_name, &augmented_classes) {
                    continue;
                }

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
                        if let Some(ref forbidden_tags) = rule.forbidden_tags {
                            for forbidden_tag in forbidden_tags {
                                if current_taints.contains(forbidden_tag) {
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

                        if let Some(ref required_tags) = rule.required_taints {
                            let all_present =
                                required_tags.iter().all(|tag| current_taints.contains(tag));

                            if all_present {
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

    /// Check tool call arguments for path traversal against `resource_rules`.
    ///
    /// Extracts string values from well-known path-like argument keys and matches them against
    /// each `ResourceRule`. First BLOCK match returns `Decision::Denied`; ALLOW rules are
    /// non-terminal (they add taints but don't terminate evaluation here). Returns `None` if
    /// no resource rules exist or no path arguments are present.
    ///
    /// Path normalization: strips `file://` and `file:///` URI prefixes before matching.
    fn evaluate_path_args(
        resource_rules: &[crate::engine_core::models::ResourceRule],
        tool_args: &Value,
    ) -> Option<Decision> {
        if resource_rules.is_empty() {
            return None;
        }

        const PATH_KEYS: &[&str] = &[
            "path",
            "file",
            "uri",
            "url",
            "filename",
            "filepath",
            "dir",
            "directory",
            "source",
            "dest",
            "destination",
            "target",
        ];

        let mut paths: Vec<String> = Vec::new();
        if let Some(obj) = tool_args.as_object() {
            for key in PATH_KEYS {
                if let Some(val) = obj.get(*key).and_then(|v| v.as_str()) {
                    // Strip scheme only (file:// → keep third slash which is the path root).
                    let normalized = val.strip_prefix("file://").unwrap_or(val).to_string();
                    paths.push(normalized);
                }
            }
        }

        if paths.is_empty() {
            return None;
        }

        for path in &paths {
            for rule in resource_rules {
                if Self::match_glob(path, &rule.uri_pattern) {
                    if rule.action == "BLOCK" {
                        return Some(Decision::Denied {
                            reason: format!(
                                "Path '{}' is blocked by resource rule: {}",
                                path, rule.uri_pattern
                            ),
                        });
                    }
                    // ALLOW rules are non-terminal for path arg checks;
                    // taint side effects are applied by the resource URI handler separately.
                    break;
                }
            }
        }
        None
    }

    /// Simple glob matching — supports `*` as a wildcard anywhere in the pattern.
    /// Mirrors `SecurityCore::match_resource_pattern` without requiring `self`.
    fn match_glob(uri: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return uri.starts_with(prefix);
        }
        if let Some(suffix) = pattern.strip_prefix('*') {
            return uri.ends_with(suffix);
        }
        if let Some((prefix, suffix)) = pattern.split_once('*') {
            return uri.starts_with(prefix) && uri.ends_with(suffix);
        }
        uri == pattern
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
