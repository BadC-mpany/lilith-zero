// Sequence and logic pattern matching for advanced rule detection

use crate::core::errors::InterceptorError;
use crate::core::models::HistoryEntry;
use serde_json::Value;
use std::collections::HashSet;

/// Pattern matcher for sequence and logic patterns
pub struct PatternMatcher;

impl PatternMatcher {
    /// Evaluate a pattern against session history and current tool
    pub fn evaluate_pattern(
        pattern: &Value,
        history: &[HistoryEntry],
        current_tool: &str,
        current_classes: &[String],
        current_taints: &HashSet<String>,
    ) -> Result<bool, InterceptorError> {
        let pattern_type = pattern
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| InterceptorError::ConfigurationError(
                "Pattern missing 'type' field".to_string()
            ))?;

        match pattern_type {
            "sequence" => Self::evaluate_sequence_pattern(
                pattern,
                history,
                current_tool,
                current_classes,
            ),
            "logic" => Self::evaluate_logic_pattern(
                pattern,
                history,
                current_tool,
                current_classes,
                current_taints,
            ),
            _ => Err(InterceptorError::ConfigurationError(
                format!("Unknown pattern type: {}", pattern_type)
            )),
        }
    }

    /// Evaluate sequence pattern: detect ordered sequences of tool executions
    fn evaluate_sequence_pattern(
        pattern: &Value,
        history: &[HistoryEntry],
        current_tool: &str,
        current_classes: &[String],
    ) -> Result<bool, InterceptorError> {
        let steps = pattern
            .get("steps")
            .and_then(|v| v.as_array())
            .ok_or_else(|| InterceptorError::ConfigurationError(
                "Sequence pattern missing 'steps' array".to_string()
            ))?;

        if steps.is_empty() {
            return Ok(false);
        }

        let max_distance = pattern
            .get("max_distance")
            .and_then(|v| v.as_i64())
            .map(|v| v as usize);

        // Build full sequence including current tool
        let mut full_sequence = history.to_vec();
        full_sequence.push(HistoryEntry {
            tool: current_tool.to_string(),
            classes: current_classes.to_vec(),
            timestamp: 0.0, // Not needed for pattern matching
        });

        Self::sequence_matches(&full_sequence, steps, max_distance)
    }

    /// Check if sequence matches the pattern steps
    fn sequence_matches(
        full_sequence: &[HistoryEntry],
        steps: &[Value],
        max_distance: Option<usize>,
    ) -> Result<bool, InterceptorError> {
        if steps.len() > full_sequence.len() {
            return Ok(false);
        }

        let mut step_idx = 0;
        let mut start_idx = 0;

        for (i, entry) in full_sequence.iter().enumerate() {
            if step_idx >= steps.len() {
                break;
            }

            if Self::entry_matches_step(entry, &steps[step_idx])? {
                if step_idx == 0 {
                    start_idx = i;
                }
                step_idx += 1;

                // Check max_distance constraint
                if let Some(max_dist) = max_distance {
                    if step_idx > 1 && (i - start_idx) > max_dist {
                        // Distance exceeded, reset
                        step_idx = 0;
                    }
                }
            }
        }

        Ok(step_idx == steps.len())
    }

    /// Check if a history entry matches a pattern step
    fn entry_matches_step(entry: &HistoryEntry, step: &Value) -> Result<bool, InterceptorError> {
        // Match by exact tool name
        if let Some(tool_name) = step.get("tool").and_then(|v| v.as_str()) {
            return Ok(entry.tool == tool_name);
        }

        // Match by tool class
        if let Some(class_name) = step.get("class").and_then(|v| v.as_str()) {
            return Ok(entry.classes.iter().any(|c| c == class_name));
        }

        Ok(false)
    }

    /// Evaluate logic pattern: boolean logic over session state
    fn evaluate_logic_pattern(
        pattern: &Value,
        history: &[HistoryEntry],
        current_tool: &str,
        current_classes: &[String],
        current_taints: &HashSet<String>,
    ) -> Result<bool, InterceptorError> {
        let condition = pattern
            .get("condition")
            .ok_or_else(|| InterceptorError::ConfigurationError(
                "Logic pattern missing 'condition' field".to_string()
            ))?;

        Self::evaluate_condition(condition, history, current_tool, current_classes, current_taints)
    }

    /// Evaluate a condition recursively (handles AND, OR, NOT)
    fn evaluate_condition(
        condition: &Value,
        history: &[HistoryEntry],
        current_tool: &str,
        current_classes: &[String],
        current_taints: &HashSet<String>,
    ) -> Result<bool, InterceptorError> {
        // Handle AND operator
        if let Some(and_array) = condition.get("AND").and_then(|v| v.as_array()) {
            for item in and_array {
                if !Self::evaluate_condition(item, history, current_tool, current_classes, current_taints)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }

        // Handle OR operator
        if let Some(or_array) = condition.get("OR").and_then(|v| v.as_array()) {
            for item in or_array {
                if Self::evaluate_condition(item, history, current_tool, current_classes, current_taints)? {
                    return Ok(true);
                }
            }
            return Ok(false);
        }

        // Handle NOT operator
        if let Some(not_value) = condition.get("NOT") {
            return Ok(!Self::evaluate_condition(not_value, history, current_tool, current_classes, current_taints)?);
        }

        // Handle atomic conditions
        Self::evaluate_atomic_condition(condition, history, current_tool, current_classes, current_taints)
    }

    /// Evaluate atomic condition (leaf node in logic tree)
    fn evaluate_atomic_condition(
        condition: &Value,
        history: &[HistoryEntry],
        current_tool: &str,
        current_classes: &[String],
        current_taints: &HashSet<String>,
    ) -> Result<bool, InterceptorError> {
        // Check: current_tool_class
        if let Some(class_name) = condition.get("current_tool_class").and_then(|v| v.as_str()) {
            return Ok(current_classes.iter().any(|c| c == class_name));
        }

        // Check: current_tool
        if let Some(tool_name) = condition.get("current_tool").and_then(|v| v.as_str()) {
            return Ok(current_tool == tool_name);
        }

        // Check: session_has_class
        if let Some(class_name) = condition.get("session_has_class").and_then(|v| v.as_str()) {
            return Ok(history.iter().any(|entry| entry.classes.iter().any(|c| c == class_name)));
        }

        // Check: session_has_tool
        if let Some(tool_name) = condition.get("session_has_tool").and_then(|v| v.as_str()) {
            return Ok(history.iter().any(|entry| entry.tool == tool_name));
        }

        // Check: session_has_taint
        if let Some(taint_name) = condition.get("session_has_taint").and_then(|v| v.as_str()) {
            return Ok(current_taints.contains(taint_name));
        }

        // Unknown condition type
        Err(InterceptorError::ConfigurationError(
            format!("Unknown atomic condition: {:?}", condition)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_sequence_pattern_matching() {
        let history = vec![
            HistoryEntry {
                tool: "read_file".to_string(),
                classes: vec!["SENSITIVE_READ".to_string()],
                timestamp: 1.0,
            },
        ];

        let pattern = json!({
            "type": "sequence",
            "steps": [
                {"class": "SENSITIVE_READ"},
                {"class": "CONSEQUENTIAL_WRITE"}
            ],
            "max_distance": null
        });

        let current_taints = HashSet::new();
        let result = PatternMatcher::evaluate_pattern(
            &pattern,
            &history,
            "web_search",
            &["CONSEQUENTIAL_WRITE".to_string()],
            &current_taints,
        ).unwrap();

        assert!(result);
    }

    #[test]
    fn test_logic_pattern_matching() {
        let history = vec![
            HistoryEntry {
                tool: "read_file".to_string(),
                classes: vec!["SENSITIVE_READ".to_string()],
                timestamp: 1.0,
            },
        ];

        let pattern = json!({
            "type": "logic",
            "condition": {
                "AND": [
                    {"session_has_class": "SENSITIVE_READ"},
                    {"current_tool_class": "HUMAN_VERIFY"}
                ]
            }
        });

        let current_taints = HashSet::new();
        let result = PatternMatcher::evaluate_pattern(
            &pattern,
            &history,
            "delete_db",
            &["HUMAN_VERIFY".to_string()],
            &current_taints,
        ).unwrap();

        assert!(result);
    }
}
