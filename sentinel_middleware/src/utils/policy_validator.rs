// Comprehensive policy validation - fail-fast at config load time

use crate::core::errors::InterceptorError;
use crate::core::models::{PolicyDefinition, PolicyRule, RuleException};
use serde_json::Value;
use std::collections::HashSet;

/// Validates policy definitions for structural correctness and semantic consistency
pub struct PolicyValidator;

impl PolicyValidator {
    /// Validate all policies - call after loading from YAML
    pub fn validate_policies(policies: &[PolicyDefinition]) -> Result<(), InterceptorError> {
        for policy in policies {
            Self::validate_policy(policy)?;
        }
        Ok(())
    }

    /// Validate a single policy definition
    fn validate_policy(policy: &PolicyDefinition) -> Result<(), InterceptorError> {
        // Policy must have a non-empty name
        if policy.name.is_empty() {
            return Err(InterceptorError::ConfigurationError(
                "Policy name cannot be empty".to_string()
            ));
        }

        // Validate static rules
        Self::validate_static_rules(&policy.static_rules, &policy.name)?;

        // Validate each taint rule
        for (idx, rule) in policy.taint_rules.iter().enumerate() {
            Self::validate_rule(rule, &policy.name, idx)?;
        }

        Ok(())
    }

    /// Validate static rules (ACL)
    fn validate_static_rules(
        static_rules: &std::collections::HashMap<String, String>,
        policy_name: &str,
    ) -> Result<(), InterceptorError> {
        for (tool_name, permission) in static_rules {
            if tool_name.is_empty() {
                return Err(InterceptorError::ConfigurationError(
                    format!("Policy '{}': static rule has empty tool name", policy_name)
                ));
            }

            match permission.as_str() {
                "ALLOW" | "DENY" => {},
                other => {
                    return Err(InterceptorError::ConfigurationError(
                        format!(
                            "Policy '{}': static rule for '{}' has invalid permission '{}' (must be ALLOW or DENY)",
                            policy_name, tool_name, other
                        )
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validate a single policy rule
    fn validate_rule(
        rule: &PolicyRule,
        policy_name: &str,
        rule_idx: usize,
    ) -> Result<(), InterceptorError> {
        let rule_context = format!("Policy '{}', rule #{}", policy_name, rule_idx + 1);

        // Rule must have exactly one of: tool OR tool_class (not both, not neither)
        match (&rule.tool, &rule.tool_class) {
            (None, None) => {
                return Err(InterceptorError::ConfigurationError(
                    format!("{}: rule must specify either 'tool' or 'tool_class'", rule_context)
                ));
            }
            (Some(_), Some(_)) => {
                return Err(InterceptorError::ConfigurationError(
                    format!("{}: rule cannot specify both 'tool' and 'tool_class'", rule_context)
                ));
            }
            _ => {} // Exactly one is set - valid
        }

        // Validate action
        Self::validate_action(&rule.action, &rule_context)?;

        // Validate action-specific requirements
        Self::validate_action_requirements(rule, &rule_context)?;

        // Validate pattern if present
        if let Some(ref pattern) = rule.pattern {
            Self::validate_pattern(pattern, &rule_context)?;
            
            // Check for tool_args_match in logic patterns (same constraint as exceptions)
            if let Some(pattern_type) = pattern.get("type").and_then(|v| v.as_str()) {
                if pattern_type == "logic" {
                    if let Some(condition) = pattern.get("condition") {
                        if Self::condition_contains_tool_args_match(condition)
                            && rule.tool_class.is_some() {
                                return Err(InterceptorError::ConfigurationError(
                                    format!(
                                        "{}: tool_args_match in logic patterns is only valid for tool-specific rules (not tool_class rules). \
                                        Tool classes have heterogeneous argument schemas.",
                                        rule_context
                                    )
                                ));
                        }
                    }
                }
            }
        }

        // Validate exceptions if present
        if let Some(ref exceptions) = rule.exceptions {
            Self::validate_exceptions(exceptions, rule, &rule_context)?;
        }

        Ok(())
    }

    /// Validate action is a known type
    fn validate_action(action: &str, context: &str) -> Result<(), InterceptorError> {
        const VALID_ACTIONS: &[&str] = &[
            "ADD_TAINT",
            "CHECK_TAINT",
            "REMOVE_TAINT",
            "BLOCK",
            "BLOCK_CURRENT",
            "BLOCK_SECOND",
        ];

        if !VALID_ACTIONS.contains(&action) {
            return Err(InterceptorError::ConfigurationError(
                format!(
                    "{}: unknown action '{}'. Valid actions: {}",
                    context,
                    action,
                    VALID_ACTIONS.join(", ")
                )
            ));
        }

        Ok(())
    }

    /// Validate action-specific requirements
    fn validate_action_requirements(rule: &PolicyRule, context: &str) -> Result<(), InterceptorError> {
        match rule.action.as_str() {
            "CHECK_TAINT" => {
                // CHECK_TAINT requires forbidden_tags
                match &rule.forbidden_tags {
                    None => {
                        return Err(InterceptorError::ConfigurationError(
                            format!("{}: CHECK_TAINT action requires 'forbidden_tags'", context)
                        ));
                    }
                    Some(tags) if tags.is_empty() => {
                        return Err(InterceptorError::ConfigurationError(
                            format!("{}: CHECK_TAINT 'forbidden_tags' cannot be empty", context)
                        ));
                    }
                    _ => {}
                }
            }
            "ADD_TAINT" | "REMOVE_TAINT" => {
                // ADD_TAINT and REMOVE_TAINT require tag
                if rule.tag.is_none() {
                    return Err(InterceptorError::ConfigurationError(
                        format!("{}: {} action requires 'tag'", context, rule.action)
                    ));
                }
            }
            "BLOCK" | "BLOCK_CURRENT" | "BLOCK_SECOND" => {
                // BLOCK actions should have a pattern (though not strictly required for simple blocks)
                // This is a soft warning - don't enforce
            }
            _ => {}
        }

        Ok(())
    }

    /// Validate pattern structure
    fn validate_pattern(pattern: &Value, context: &str) -> Result<(), InterceptorError> {
        // Pattern must have 'type' field
        let pattern_type = pattern
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| InterceptorError::ConfigurationError(
                format!("{}: pattern missing 'type' field", context)
            ))?;

        match pattern_type {
            "sequence" => Self::validate_sequence_pattern(pattern, context)?,
            "logic" => Self::validate_logic_pattern(pattern, context)?,
            other => {
                return Err(InterceptorError::ConfigurationError(
                    format!(
                        "{}: unknown pattern type '{}' (must be 'sequence' or 'logic')",
                        context, other
                    )
                ));
            }
        }

        Ok(())
    }

    /// Validate sequence pattern
    fn validate_sequence_pattern(pattern: &Value, context: &str) -> Result<(), InterceptorError> {
        // Must have 'steps' array
        let steps = pattern
            .get("steps")
            .and_then(|v| v.as_array())
            .ok_or_else(|| InterceptorError::ConfigurationError(
                format!("{}: sequence pattern missing 'steps' array", context)
            ))?;

        if steps.is_empty() {
            return Err(InterceptorError::ConfigurationError(
                format!("{}: sequence pattern 'steps' cannot be empty", context)
            ));
        }

        // Validate each step
        for (idx, step) in steps.iter().enumerate() {
            let step_obj = step.as_object().ok_or_else(|| {
                InterceptorError::ConfigurationError(
                    format!("{}: sequence step #{} must be an object", context, idx + 1)
                )
            })?;

            // Each step must have either 'tool' or 'class'
            let has_tool = step_obj.contains_key("tool");
            let has_class = step_obj.contains_key("class");

            if !has_tool && !has_class {
                return Err(InterceptorError::ConfigurationError(
                    format!(
                        "{}: sequence step #{} must have either 'tool' or 'class'",
                        context,
                        idx + 1
                    )
                ));
            }
        }

        Ok(())
    }

    /// Validate logic pattern
    fn validate_logic_pattern(pattern: &Value, context: &str) -> Result<(), InterceptorError> {
        // Must have 'condition' field
        let condition = pattern
            .get("condition")
            .ok_or_else(|| InterceptorError::ConfigurationError(
                format!("{}: logic pattern missing 'condition' field", context)
            ))?;

        // Validate condition structure
        Self::validate_condition(condition, context)?;

        Ok(())
    }

    /// Validate condition structure (recursive)
    fn validate_condition(condition: &Value, context: &str) -> Result<(), InterceptorError> {
        let obj = condition.as_object().ok_or_else(|| {
            InterceptorError::ConfigurationError(
                format!("{}: condition must be an object", context)
            )
        })?;

        // Check for logical operators
        if let Some(and_array) = obj.get("AND").and_then(|v| v.as_array()) {
            if and_array.is_empty() {
                return Err(InterceptorError::ConfigurationError(
                    format!("{}: AND operator cannot have empty array", context)
                ));
            }
            for item in and_array {
                Self::validate_condition(item, context)?;
            }
            return Ok(());
        }

        if let Some(or_array) = obj.get("OR").and_then(|v| v.as_array()) {
            if or_array.is_empty() {
                return Err(InterceptorError::ConfigurationError(
                    format!("{}: OR operator cannot have empty array", context)
                ));
            }
            for item in or_array {
                Self::validate_condition(item, context)?;
            }
            return Ok(());
        }

        if let Some(not_value) = obj.get("NOT") {
            Self::validate_condition(not_value, context)?;
            return Ok(());
        }

        // If not a logical operator, validate as atomic condition
        Self::validate_atomic_condition(obj, context)?;

        Ok(())
    }

    /// Validate atomic condition
    fn validate_atomic_condition(
        condition: &serde_json::Map<String, Value>,
        context: &str,
    ) -> Result<(), InterceptorError> {
        const VALID_ATOMIC_CONDITIONS: &[&str] = &[
            "current_tool_class",
            "current_tool",
            "session_has_class",
            "session_has_tool",
            "session_has_taint",
            "tool_args_match",
        ];

        // Must have exactly one valid atomic condition key
        let matching_keys: Vec<_> = condition
            .keys()
            .filter(|k| VALID_ATOMIC_CONDITIONS.contains(&k.as_str()))
            .collect();

        if matching_keys.is_empty() {
            return Err(InterceptorError::ConfigurationError(
                format!(
                    "{}: condition must contain one of: {}",
                    context,
                    VALID_ATOMIC_CONDITIONS.join(", ")
                )
            ));
        }

        if matching_keys.len() > 1 {
            return Err(InterceptorError::ConfigurationError(
                format!(
                    "{}: condition has multiple atomic keys: {:?}",
                    context, matching_keys
                )
            ));
        }

        Ok(())
    }

    /// Validate exceptions
    fn validate_exceptions(
        exceptions: &[RuleException],
        rule: &PolicyRule,
        context: &str,
    ) -> Result<(), InterceptorError> {
        for (idx, exception) in exceptions.iter().enumerate() {
            let exc_context = format!("{}, exception #{}", context, idx + 1);

            // Validate exception condition
            Self::validate_condition(&exception.condition, &exc_context)?;

            // CRITICAL: tool_args_match only allowed in tool-specific rules
            if Self::condition_contains_tool_args_match(&exception.condition) {
                if rule.tool_class.is_some() {
                    return Err(InterceptorError::ConfigurationError(
                        format!(
                            "{}: tool_args_match in exceptions is only valid for tool-specific rules (not tool_class rules). \
                            Tool classes have heterogeneous argument schemas.",
                            exc_context
                        )
                    ));
                }

                // Also verify rule.tool is Some (should already be guaranteed by earlier checks)
                if rule.tool.is_none() {
                    return Err(InterceptorError::ConfigurationError(
                        format!(
                            "{}: tool_args_match requires rule to specify 'tool' field",
                            exc_context
                        )
                    ));
                }
            }
        }

        Ok(())
    }

    /// Recursively check if condition contains tool_args_match
    fn condition_contains_tool_args_match(condition: &Value) -> bool {
        if let Some(obj) = condition.as_object() {
            // Check for tool_args_match directly
            if obj.contains_key("tool_args_match") {
                return true;
            }

            // Check AND/OR/NOT operators recursively
            if let Some(and_array) = obj.get("AND").and_then(|v| v.as_array()) {
                return and_array.iter().any(Self::condition_contains_tool_args_match);
            }

            if let Some(or_array) = obj.get("OR").and_then(|v| v.as_array()) {
                return or_array.iter().any(Self::condition_contains_tool_args_match);
            }

            if let Some(not_value) = obj.get("NOT") {
                return Self::condition_contains_tool_args_match(not_value);
            }
        }

        false
    }

    /// Validate that referenced tool classes exist in the tool registry (optional check)
    pub fn validate_tool_classes(
        policies: &[PolicyDefinition],
        known_classes: &HashSet<String>,
    ) -> Result<(), InterceptorError> {
        for policy in policies {
            for (idx, rule) in policy.taint_rules.iter().enumerate() {
                if let Some(ref class) = rule.tool_class {
                    if !known_classes.contains(class) {
                        return Err(InterceptorError::ConfigurationError(
                            format!(
                                "Policy '{}', rule #{}: unknown tool class '{}'. \
                                Known classes: {:?}",
                                policy.name,
                                idx + 1,
                                class,
                                known_classes
                            )
                        ));
                    }
                }

                // Also check classes in patterns
                if let Some(ref pattern) = rule.pattern {
                    Self::validate_pattern_classes(pattern, &policy.name, idx, known_classes)?;
                }
            }
        }

        Ok(())
    }

    /// Validate tool classes referenced in patterns
    fn validate_pattern_classes(
        pattern: &Value,
        policy_name: &str,
        rule_idx: usize,
        known_classes: &HashSet<String>,
    ) -> Result<(), InterceptorError> {
        if let Some(steps) = pattern.get("steps").and_then(|v| v.as_array()) {
            for step in steps {
                if let Some(class_name) = step.get("class").and_then(|v| v.as_str()) {
                    if !known_classes.contains(class_name) {
                        return Err(InterceptorError::ConfigurationError(
                            format!(
                                "Policy '{}', rule #{}: unknown tool class '{}' in pattern. \
                                Known classes: {:?}",
                                policy_name,
                                rule_idx + 1,
                                class_name,
                                known_classes
                            )
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn test_valid_policy() {
        let mut static_rules = HashMap::new();
        static_rules.insert("read_file".to_string(), "ALLOW".to_string());

        let policy = PolicyDefinition {
            name: "test_policy".to_string(),
            static_rules,
            taint_rules: vec![
                PolicyRule {
                    tool: Some("read_file".to_string()),
                    tool_class: None,
                    action: "ADD_TAINT".to_string(),
                    tag: Some("sensitive".to_string()),
                    forbidden_tags: None,
                    error: None,
                    pattern: None,
                    exceptions: None,
                },
            ],
        };

        assert!(PolicyValidator::validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_rule_needs_tool_or_class() {
        let policy = PolicyDefinition {
            name: "test".to_string(),
            static_rules: HashMap::new(),
            taint_rules: vec![
                PolicyRule {
                    tool: None,
                    tool_class: None, // Missing both!
                    action: "ADD_TAINT".to_string(),
                    tag: Some("test".to_string()),
                    forbidden_tags: None,
                    error: None,
                    pattern: None,
                    exceptions: None,
                },
            ],
        };

        let result = PolicyValidator::validate_policy(&policy);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must specify either 'tool' or 'tool_class'"));
    }

    #[test]
    fn test_check_taint_requires_forbidden_tags() {
        let policy = PolicyDefinition {
            name: "test".to_string(),
            static_rules: HashMap::new(),
            taint_rules: vec![
                PolicyRule {
                    tool: Some("test_tool".to_string()),
                    tool_class: None,
                    action: "CHECK_TAINT".to_string(),
                    tag: None,
                    forbidden_tags: None, // Missing!
                    error: None,
                    pattern: None,
                    exceptions: None,
                },
            ],
        };

        let result = PolicyValidator::validate_policy(&policy);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("requires 'forbidden_tags'"));
    }

    #[test]
    fn test_tool_args_match_not_allowed_in_class_rules() {
        use crate::core::models::RuleException;

        let policy = PolicyDefinition {
            name: "test".to_string(),
            static_rules: HashMap::new(),
            taint_rules: vec![
                PolicyRule {
                    tool: None,
                    tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
                    action: "CHECK_TAINT".to_string(),
                    tag: None,
                    forbidden_tags: Some(vec!["sensitive".to_string()]),
                    error: None,
                    pattern: None,
                    exceptions: Some(vec![
                        RuleException {
                            condition: json!({
                                "tool_args_match": {"destination": "internal_*"}
                            }),
                            reason: Some("test".to_string()),
                        },
                    ]),
                },
            ],
        };

        let result = PolicyValidator::validate_policy(&policy);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("tool_args_match"));
        assert!(err_msg.contains("tool-specific rules"));
    }

    #[test]
    fn test_tool_args_match_allowed_in_tool_rules() {
        use crate::core::models::RuleException;

        let policy = PolicyDefinition {
            name: "test".to_string(),
            static_rules: HashMap::new(),
            taint_rules: vec![
                PolicyRule {
                    tool: Some("send_email".to_string()),
                    tool_class: None,
                    action: "CHECK_TAINT".to_string(),
                    tag: None,
                    forbidden_tags: Some(vec!["sensitive".to_string()]),
                    error: None,
                    pattern: None,
                    exceptions: Some(vec![
                        RuleException {
                            condition: json!({
                                "tool_args_match": {"to": "*@company.com"}
                            }),
                            reason: Some("Internal emails allowed".to_string()),
                        },
                    ]),
                },
            ],
        };

        assert!(PolicyValidator::validate_policy(&policy).is_ok());
    }
}

