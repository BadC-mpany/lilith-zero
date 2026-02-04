// Comprehensive policy validation - fail-fast at config load time

use crate::core::errors::InterceptorError;
use crate::core::models::{PolicyDefinition, PolicyRule, RuleException, LogicCondition};

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
                "Policy name cannot be empty".to_string(),
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
                return Err(InterceptorError::ConfigurationError(format!(
                    "Policy '{}': static rule has empty tool name",
                    policy_name
                )));
            }

            match permission.as_str() {
                "ALLOW" | "DENY" => {}
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
                return Err(InterceptorError::ConfigurationError(format!(
                    "{}: rule must specify either 'tool' or 'tool_class'",
                    rule_context
                )));
            }
            (Some(_), Some(_)) => {
                return Err(InterceptorError::ConfigurationError(format!(
                    "{}: rule cannot specify both 'tool' and 'tool_class'",
                    rule_context
                )));
            }
            _ => {} // Exactly one is set - valid
        }

        // Validate action
        Self::validate_action(&rule.action, &rule_context)?;

        // Validate action-specific requirements
        Self::validate_action_requirements(rule, &rule_context)?;

        // Validate pattern if present
        if let Some(ref pattern) = rule.pattern {
            // LogicCondition IS the pattern. No need to check "type": "logic".
            // We just validate the condition structure.
            Self::validate_condition(pattern, &rule_context)?;

            // Check for tool_args_match in logic patterns
            if Self::condition_contains_tool_args_match(pattern)
                && rule.tool_class.is_some()
            {
                return Err(InterceptorError::ConfigurationError(
                        format!(
                            "{}: tool_args_match in logic patterns is only valid for tool-specific rules (not tool_class rules). \
                            Tool classes have heterogeneous argument schemas.",
                            rule_context
                        )
                    ));
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
            return Err(InterceptorError::ConfigurationError(format!(
                "{}: unknown action '{}'. Valid actions: {}",
                context,
                action,
                VALID_ACTIONS.join(", ")
            )));
        }

        Ok(())
    }

    /// Validate action-specific requirements
    fn validate_action_requirements(
        rule: &PolicyRule,
        context: &str,
    ) -> Result<(), InterceptorError> {
        match rule.action.as_str() {
            "CHECK_TAINT" => {
                // CHECK_TAINT requires forbidden_tags
                match &rule.forbidden_tags {
                    None => {
                        return Err(InterceptorError::ConfigurationError(format!(
                            "{}: CHECK_TAINT action requires 'forbidden_tags'",
                            context
                        )));
                    }
                    Some(tags) if tags.is_empty() => {
                        return Err(InterceptorError::ConfigurationError(format!(
                            "{}: CHECK_TAINT 'forbidden_tags' cannot be empty",
                            context
                        )));
                    }
                    _ => {}
                }
            }
            "ADD_TAINT" | "REMOVE_TAINT" => {
                // ADD_TAINT and REMOVE_TAINT require tag
                if rule.tag.is_none() {
                    return Err(InterceptorError::ConfigurationError(format!(
                        "{}: {} action requires 'tag'",
                        context, rule.action
                    )));
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

    /// Validate condition structure (recursive)
    fn validate_condition(condition: &LogicCondition, _context: &str) -> Result<(), InterceptorError> {
        match condition {
             LogicCondition::And(rules) | LogicCondition::Or(rules) => {
                 for rule in rules {
                     Self::validate_condition(rule, _context)?;
                 }
             },
             LogicCondition::Not(rule) => {
                 Self::validate_condition(rule, _context)?;
             },
             LogicCondition::Eq(_) | LogicCondition::Neq(_) | 
             LogicCondition::Gt(_) | LogicCondition::Lt(_) |
             LogicCondition::ToolArgsMatch(_) => {
                // Leaf nodes are valid by definition in this schema
             },
             LogicCondition::Literal(_) => {},
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
                    return Err(InterceptorError::ConfigurationError(format!(
                        "{}: tool_args_match requires rule to specify 'tool' field",
                        exc_context
                    )));
                }
            }
        }

        Ok(())
    }

    /// Recursively check if condition contains tool_args_match
    fn condition_contains_tool_args_match(condition: &LogicCondition) -> bool {
        match condition {
            LogicCondition::And(rules) | LogicCondition::Or(rules) => {
                rules.iter().any(Self::condition_contains_tool_args_match)
            },
            LogicCondition::Not(rule) => Self::condition_contains_tool_args_match(rule),
            LogicCondition::ToolArgsMatch(_) => true,
            _ => false 
        }
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
                        return Err(InterceptorError::ConfigurationError(format!(
                            "Policy '{}', rule #{}: unknown tool class '{}'. \
                                Known classes: {:?}",
                            policy.name,
                            idx + 1,
                            class,
                            known_classes
                        )));
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
    use serde_json::{json, from_value};
    use std::collections::HashMap;

    #[test]
    fn test_valid_policy() {
        let mut static_rules = HashMap::new();
        static_rules.insert("read_file".to_string(), "ALLOW".to_string());

        let policy = PolicyDefinition {

            id: "test-policy".to_string(),
            customer_id: "test-customer".to_string(),
            name: "test_policy".to_string(),
            version: 1,
            static_rules,
            resource_rules: vec![],
            taint_rules: vec![PolicyRule {
                tool: Some("read_file".to_string()),
                tool_class: None,
                action: "ADD_TAINT".to_string(),
                tag: Some("sensitive".to_string()),
                forbidden_tags: None,
                error: None,
                pattern: None,
                exceptions: None,
            }],
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
        };

        assert!(PolicyValidator::validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_rule_needs_tool_or_class() {
        let policy = PolicyDefinition {
            id: "test-policy".to_string(),
            customer_id: "test-customer".to_string(),
            name: "test".to_string(),
            version: 1,
            static_rules: HashMap::new(),
            resource_rules: vec![],
            taint_rules: vec![PolicyRule {
                tool: None,
                tool_class: None, // Missing both!
                action: "ADD_TAINT".to_string(),
                tag: Some("test".to_string()),
                forbidden_tags: None,
                error: None,
                pattern: None,
                exceptions: None,
            }],
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
        };

        let result = PolicyValidator::validate_policy(&policy);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must specify either 'tool' or 'tool_class'"));
    }

    #[test]
    fn test_check_taint_requires_forbidden_tags() {
        let policy = PolicyDefinition {
            id: "test-policy".to_string(),
            customer_id: "test-customer".to_string(),
            name: "test".to_string(),
            version: 1,
            static_rules: HashMap::new(),
            resource_rules: vec![],
            taint_rules: vec![PolicyRule {
                tool: Some("test_tool".to_string()),
                tool_class: None,
                action: "CHECK_TAINT".to_string(),
                tag: None,
                forbidden_tags: None, // Missing!
                error: None,
                pattern: None,
                exceptions: None,
            }],
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
        };

        let result = PolicyValidator::validate_policy(&policy);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("requires 'forbidden_tags'"));
    }

    #[test]
    fn test_tool_args_match_not_allowed_in_class_rules() {
        use crate::core::models::RuleException;

        let policy = PolicyDefinition {
            id: "test-policy".to_string(),
            customer_id: "test-customer".to_string(),
            name: "test".to_string(),
            version: 1,
            static_rules: HashMap::new(),
            resource_rules: vec![],
            taint_rules: vec![PolicyRule {
                tool: None,
                tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
                action: "CHECK_TAINT".to_string(),
                tag: None,
                forbidden_tags: Some(vec!["sensitive".to_string()]),
                error: None,
                pattern: None,
                exceptions: Some(vec![RuleException {
                    condition: from_value(json!({
                        "tool_args_match": {"destination": "internal_*"}
                    })).unwrap(),
                    reason: Some("test".to_string()),
                }]),
            }],
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
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
            id: "test-policy".to_string(),
            customer_id: "test-customer".to_string(),
            name: "test".to_string(),
            version: 1,
            static_rules: HashMap::new(),
            resource_rules: vec![],
            taint_rules: vec![PolicyRule {
                tool: Some("send_email".to_string()),
                tool_class: None,
                action: "CHECK_TAINT".to_string(),
                tag: None,
                forbidden_tags: Some(vec!["sensitive".to_string()]),
                error: None,
                pattern: None,
                exceptions: Some(vec![RuleException {
                    condition: from_value(json!({
                        "tool_args_match": {"to": "*@company.com"}
                    })).unwrap(),
                    reason: Some("Internal emails allowed".to_string()),
                }]),
            }],
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
        };

        assert!(PolicyValidator::validate_policy(&policy).is_ok());
    }
}
