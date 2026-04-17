// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::engine_core::errors::InterceptorError;
use crate::engine_core::models::{LogicCondition, PolicyDefinition, PolicyRule, RuleException};

use std::collections::HashSet;

/// Severity of a [`PolicyValidationError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    /// The policy is structurally invalid and cannot be safely loaded.
    Error,
    /// The policy can be loaded but may behave unexpectedly.
    Warning,
}

/// A structured validation diagnostic emitted by [`PolicyValidator::validate_policy_detailed`].
#[derive(Debug, Clone)]
pub struct PolicyValidationError {
    /// Dot-notation path to the offending field (e.g. `"taintRules[2].action"`).
    pub field_path: String,
    /// Zero-based index of the offending rule, if applicable.
    pub rule_index: Option<usize>,
    /// Human-readable description of the problem.
    pub message: String,
    /// Optional actionable suggestion for fixing the problem.
    pub suggestion: Option<String>,
    /// Whether this is a hard error or a non-fatal warning.
    pub severity: ValidationSeverity,
}

impl PolicyValidationError {
    fn error(
        field_path: impl Into<String>,
        rule_index: Option<usize>,
        message: impl Into<String>,
        suggestion: Option<&str>,
    ) -> Self {
        Self {
            field_path: field_path.into(),
            rule_index,
            message: message.into(),
            suggestion: suggestion.map(str::to_string),
            severity: ValidationSeverity::Error,
        }
    }

    fn warning(
        field_path: impl Into<String>,
        rule_index: Option<usize>,
        message: impl Into<String>,
        suggestion: Option<&str>,
    ) -> Self {
        Self {
            field_path: field_path.into(),
            rule_index,
            message: message.into(),
            suggestion: suggestion.map(str::to_string),
            severity: ValidationSeverity::Warning,
        }
    }
}

impl std::fmt::Display for PolicyValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}] {}: {}",
            self.severity, self.field_path, self.message
        )?;
        if let Some(ref s) = self.suggestion {
            write!(f, " (suggestion: {})", s)?;
        }
        Ok(())
    }
}

/// Validates [`PolicyDefinition`] structures for structural correctness before use.
pub struct PolicyValidator;

impl PolicyValidator {
    /// Validate a slice of [`PolicyDefinition`]s, returning the first error encountered.
    pub fn validate_policies(policies: &[PolicyDefinition]) -> Result<(), InterceptorError> {
        for policy in policies {
            Self::validate_policy(policy)?;
        }
        Ok(())
    }

    fn validate_policy(policy: &PolicyDefinition) -> Result<(), InterceptorError> {
        if policy.name.is_empty() {
            return Err(InterceptorError::ConfigurationError(
                "Policy name cannot be empty".to_string(),
            ));
        }

        Self::validate_static_rules(&policy.static_rules, &policy.name)?;

        for (idx, rule) in policy.taint_rules.iter().enumerate() {
            Self::validate_rule(rule, &policy.name, idx)?;
        }

        Ok(())
    }

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

    fn validate_rule(
        rule: &PolicyRule,
        policy_name: &str,
        rule_idx: usize,
    ) -> Result<(), InterceptorError> {
        let rule_context = format!("Policy '{}', rule #{}", policy_name, rule_idx + 1);

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

        Self::validate_action(&rule.action, &rule_context)?;

        Self::validate_action_requirements(rule, &rule_context)?;

        if let Some(ref pattern) = rule.pattern {
            Self::validate_condition(pattern, &rule_context)?;

            if Self::condition_contains_tool_args_match(pattern) && rule.tool_class.is_some() {
                return Err(InterceptorError::ConfigurationError(
                        format!(
                            "{}: tool_args_match in logic patterns is only valid for tool-specific rules (not tool_class rules). \
                            Tool classes have heterogeneous argument schemas.",
                            rule_context
                        )
                    ));
            }
        }

        if let Some(ref exceptions) = rule.exceptions {
            Self::validate_exceptions(exceptions, rule, &rule_context)?;
        }

        Ok(())
    }

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

    fn validate_action_requirements(
        rule: &PolicyRule,
        context: &str,
    ) -> Result<(), InterceptorError> {
        match rule.action.as_str() {
            "CHECK_TAINT" => {
                let has_forbidden = rule
                    .forbidden_tags
                    .as_ref()
                    .is_some_and(|tags| !tags.is_empty());
                let has_required = rule
                    .required_taints
                    .as_ref()
                    .is_some_and(|tags| !tags.is_empty());

                if !has_forbidden && !has_required {
                    return Err(InterceptorError::ConfigurationError(format!(
                        "{}: CHECK_TAINT action requires either 'forbidden_tags' or 'required_taints'",
                        context
                    )));
                }
            }
            "ADD_TAINT" | "REMOVE_TAINT" if rule.tag.is_none() => {
                return Err(InterceptorError::ConfigurationError(format!(
                    "{}: {} action requires 'tag'",
                    context, rule.action
                )));
            }
            "BLOCK" | "BLOCK_CURRENT" | "BLOCK_SECOND" => {}
            _ => {}
        }

        Ok(())
    }

    fn validate_condition(
        condition: &LogicCondition,
        _context: &str,
    ) -> Result<(), InterceptorError> {
        match condition {
            LogicCondition::And(rules) | LogicCondition::Or(rules) => {
                for rule in rules {
                    Self::validate_condition(rule, _context)?;
                }
            }
            LogicCondition::Not(rule) => {
                Self::validate_condition(rule, _context)?;
            }
            LogicCondition::Eq(_)
            | LogicCondition::Neq(_)
            | LogicCondition::Gt(_)
            | LogicCondition::Lt(_)
            | LogicCondition::ToolArgsMatch(_) => {}
            LogicCondition::Literal(_) => {}
        }
        Ok(())
    }

    fn validate_exceptions(
        exceptions: &[RuleException],
        rule: &PolicyRule,
        context: &str,
    ) -> Result<(), InterceptorError> {
        for (idx, exception) in exceptions.iter().enumerate() {
            let exc_context = format!("{}, exception #{}", context, idx + 1);

            Self::validate_condition(&exception.condition, &exc_context)?;

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

    fn condition_contains_tool_args_match(condition: &LogicCondition) -> bool {
        match condition {
            LogicCondition::And(rules) | LogicCondition::Or(rules) => {
                rules.iter().any(Self::condition_contains_tool_args_match)
            }
            LogicCondition::Not(rule) => Self::condition_contains_tool_args_match(rule),
            LogicCondition::ToolArgsMatch(_) => true,
            _ => false,
        }
    }

    /// Cross-validate that all `tool_class` values referenced in `policies` exist in
    /// `known_classes`, returning the first error if any unknown class is found.
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

    /// Validate a slice of policies and return all structured diagnostics (errors and warnings).
    ///
    /// Unlike [`Self::validate_policies`] this does **not** fail-fast: it collects every
    /// diagnostic so the operator can fix all problems in one edit cycle.
    pub fn validate_policies_detailed(policies: &[PolicyDefinition]) -> Vec<PolicyValidationError> {
        let mut out = Vec::new();
        for policy in policies {
            out.extend(Self::validate_policy_detailed(policy));
        }
        out
    }

    /// Validate a single [`PolicyDefinition`] and return all structured diagnostics.
    pub fn validate_policy_detailed(policy: &PolicyDefinition) -> Vec<PolicyValidationError> {
        let mut out = Vec::new();

        if policy.name.is_empty() {
            out.push(PolicyValidationError::error(
                "name",
                None,
                "Policy name cannot be empty",
                Some("Set 'name' to a non-empty string"),
            ));
        }

        // Static rules
        for (tool_name, permission) in &policy.static_rules {
            if tool_name.is_empty() {
                out.push(PolicyValidationError::error(
                    "staticRules",
                    None,
                    "Static rule has an empty tool name key",
                    Some("Replace the empty string key with the tool name"),
                ));
            }
            match permission.as_str() {
                "ALLOW" | "DENY" => {}
                other => {
                    out.push(PolicyValidationError::error(
                        format!("staticRules[\"{}\"]", tool_name),
                        None,
                        format!("Invalid permission '{}' (must be ALLOW or DENY)", other),
                        Some("Use 'ALLOW' or 'DENY'"),
                    ));
                }
            }
        }

        // Taint rules
        for (idx, rule) in policy.taint_rules.iter().enumerate() {
            let prefix = format!("taintRules[{}]", idx);
            Self::collect_rule_errors(rule, idx, &prefix, &mut out);
        }

        out
    }

    fn collect_rule_errors(
        rule: &PolicyRule,
        idx: usize,
        prefix: &str,
        out: &mut Vec<PolicyValidationError>,
    ) {
        match (&rule.tool, &rule.tool_class) {
            (None, None) => {
                out.push(PolicyValidationError::error(
                    format!("{}.tool", prefix),
                    Some(idx),
                    "Rule must specify either 'tool' or 'tool_class'",
                    Some("Add 'tool: \"my_tool_name\"' or 'tool_class: \"MY_CLASS\"'"),
                ));
            }
            (Some(_), Some(_)) => {
                out.push(PolicyValidationError::error(
                    format!("{}.tool", prefix),
                    Some(idx),
                    "Rule cannot specify both 'tool' and 'tool_class'",
                    Some("Remove one of 'tool' or 'tool_class'"),
                ));
            }
            _ => {}
        }

        const VALID_ACTIONS: &[&str] = &[
            "ADD_TAINT",
            "CHECK_TAINT",
            "REMOVE_TAINT",
            "BLOCK",
            "BLOCK_CURRENT",
            "BLOCK_SECOND",
        ];
        if !VALID_ACTIONS.contains(&rule.action.as_str()) {
            out.push(PolicyValidationError::error(
                format!("{}.action", prefix),
                Some(idx),
                format!(
                    "Unknown action '{}'. Valid actions: {}",
                    rule.action,
                    VALID_ACTIONS.join(", ")
                ),
                Some("Use ADD_TAINT, CHECK_TAINT, REMOVE_TAINT, or BLOCK"),
            ));
        }

        match rule.action.as_str() {
            "CHECK_TAINT" => {
                let has_forbidden = rule.forbidden_tags.as_ref().is_some_and(|t| !t.is_empty());
                let has_required = rule.required_taints.as_ref().is_some_and(|t| !t.is_empty());
                if !has_forbidden && !has_required {
                    out.push(PolicyValidationError::error(
                        format!("{}.forbidden_tags", prefix),
                        Some(idx),
                        "CHECK_TAINT requires 'forbidden_tags' or 'required_taints'",
                        Some(
                            "Add 'forbidden_tags: [\"MY_TAG\"]' to block when that taint is present",
                        ),
                    ));
                }
            }
            "ADD_TAINT" | "REMOVE_TAINT" if rule.tag.is_none() => {
                out.push(PolicyValidationError::error(
                    format!("{}.tag", prefix),
                    Some(idx),
                    format!("'{}' action requires 'tag'", rule.action),
                    Some("Add 'tag: \"MY_TAINT_TAG\"'"),
                ));
            }
            _ => {}
        }

        if let Some(ref pattern) = rule.pattern {
            if Self::condition_contains_tool_args_match(pattern) && rule.tool_class.is_some() {
                out.push(PolicyValidationError::error(
                    format!("{}.pattern", prefix),
                    Some(idx),
                    "tool_args_match in logic patterns is only valid for tool-specific rules, \
                     not tool_class rules (heterogeneous argument schemas)",
                    Some("Use 'tool' instead of 'tool_class', or remove the tool_args_match condition"),
                ));
            }
        }

        if let Some(ref exceptions) = rule.exceptions {
            for (eidx, exc) in exceptions.iter().enumerate() {
                let exc_prefix = format!("{}.exceptions[{}]", prefix, eidx);
                if Self::condition_contains_tool_args_match(&exc.condition) {
                    if rule.tool_class.is_some() {
                        out.push(PolicyValidationError::error(
                            format!("{}.condition", exc_prefix),
                            Some(idx),
                            "tool_args_match in exceptions is only valid for tool-specific rules",
                            Some("Use 'tool' instead of 'tool_class'"),
                        ));
                    }
                    if rule.tool.is_none() {
                        out.push(PolicyValidationError::error(
                            format!("{}.condition", exc_prefix),
                            Some(idx),
                            "tool_args_match requires the rule to specify 'tool'",
                            Some("Add 'tool: \"my_tool_name\"' to this rule"),
                        ));
                    }
                }
            }
        }

        // Warning: BLOCK rules without an error message produce opaque denials.
        if (rule.action == "BLOCK"
            || rule.action == "BLOCK_CURRENT"
            || rule.action == "BLOCK_SECOND")
            && rule.error.is_none()
        {
            out.push(PolicyValidationError::warning(
                format!("{}.error", prefix),
                Some(idx),
                "BLOCK rule has no 'error' message — agents will receive a generic denial",
                Some("Add 'error: \"human-readable reason\"' for better agent UX"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_value, json};
    use std::collections::HashMap;

    #[test]
    fn test_valid_policy() {
        let mut static_rules = HashMap::new();
        static_rules.insert("read_file".to_string(), "ALLOW".to_string());

        let policy = PolicyDefinition {
            id: "test-policy".to_string(),
            customer_id: "test-customer".to_string(),
            name: "test_policy".to_string(),
            description: None,
            schema_version: None,
            version: 1,
            static_rules,
            resource_rules: vec![],
            taint_rules: vec![PolicyRule {
                tool: Some("read_file".to_string()),
                tool_class: None,
                action: "ADD_TAINT".to_string(),
                tag: Some("sensitive".to_string()),
                forbidden_tags: None,
                required_taints: None,
                error: None,
                pattern: None,
                exceptions: None,
            }],
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
            protect_lethal_trifecta: false,
        };

        assert!(PolicyValidator::validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_rule_needs_tool_or_class() {
        let policy = PolicyDefinition {
            id: "test-policy".to_string(),
            customer_id: "test-customer".to_string(),
            name: "test".to_string(),
            description: None,
            schema_version: None,
            version: 1,
            static_rules: HashMap::new(),
            resource_rules: vec![],
            taint_rules: vec![PolicyRule {
                tool: None,
                tool_class: None, // Missing both!
                action: "ADD_TAINT".to_string(),
                tag: Some("test".to_string()),
                forbidden_tags: None,
                required_taints: None,
                error: None,
                pattern: None,
                exceptions: None,
            }],
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
            protect_lethal_trifecta: false,
        };

        let result = PolicyValidator::validate_policy(&policy);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must specify either 'tool' or 'tool_class'"));
    }

    #[test]
    fn test_check_taint_requires_forbidden_tags() {
        let policy = PolicyDefinition {
            id: "test-policy".to_string(),
            customer_id: "test-customer".to_string(),
            name: "test".to_string(),
            description: None,
            schema_version: None,
            version: 1,
            static_rules: HashMap::new(),
            resource_rules: vec![],
            taint_rules: vec![PolicyRule {
                tool: Some("test_tool".to_string()),
                tool_class: None,
                action: "CHECK_TAINT".to_string(),
                tag: None,
                forbidden_tags: None, // Missing!
                required_taints: None,
                error: None,
                pattern: None,
                exceptions: None,
            }],
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
            protect_lethal_trifecta: false,
        };

        let result = PolicyValidator::validate_policy(&policy);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("forbidden_tags") || err_msg.contains("required_taints"));
    }

    #[test]
    fn test_tool_args_match_not_allowed_in_class_rules() {
        use crate::engine_core::models::RuleException;

        let policy = PolicyDefinition {
            id: "test-policy".to_string(),
            customer_id: "test-customer".to_string(),
            name: "test".to_string(),
            description: None,
            schema_version: None,
            version: 1,
            static_rules: HashMap::new(),
            resource_rules: vec![],
            taint_rules: vec![PolicyRule {
                tool: None,
                tool_class: Some("CONSEQUENTIAL_WRITE".to_string()),
                action: "CHECK_TAINT".to_string(),
                tag: None,
                forbidden_tags: Some(vec!["sensitive".to_string()]),
                required_taints: None,
                error: None,
                pattern: None,
                exceptions: Some(vec![RuleException {
                    condition: from_value(json!({
                        "tool_args_match": {"destination": "internal_*"}
                    }))
                    .unwrap(),
                    reason: Some("test".to_string()),
                }]),
            }],
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
            protect_lethal_trifecta: false,
        };

        let result = PolicyValidator::validate_policy(&policy);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("tool_args_match"));
        assert!(err_msg.contains("tool-specific rules"));
    }

    #[test]
    fn test_tool_args_match_allowed_in_tool_rules() {
        use crate::engine_core::models::RuleException;

        let policy = PolicyDefinition {
            id: "test-policy".to_string(),
            customer_id: "test-customer".to_string(),
            name: "test".to_string(),
            description: None,
            schema_version: None,
            version: 1,
            static_rules: HashMap::new(),
            resource_rules: vec![],
            taint_rules: vec![PolicyRule {
                tool: Some("send_email".to_string()),
                tool_class: None,
                action: "CHECK_TAINT".to_string(),
                tag: None,
                forbidden_tags: Some(vec!["sensitive".to_string()]),
                required_taints: None,
                error: None,
                pattern: None,
                exceptions: Some(vec![RuleException {
                    condition: from_value(json!({
                        "tool_args_match": {"to": "*@company.com"}
                    }))
                    .unwrap(),
                    reason: Some("Internal emails allowed".to_string()),
                }]),
            }],
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
            protect_lethal_trifecta: false,
        };

        assert!(PolicyValidator::validate_policy(&policy).is_ok());
    }

    // --- Tests for structured (detailed) validation ---

    fn minimal_policy(taint_rules: Vec<PolicyRule>) -> PolicyDefinition {
        PolicyDefinition {
            id: "test".to_string(),
            customer_id: "test".to_string(),
            name: "test".to_string(),
            description: None,
            schema_version: None,
            version: 1,
            static_rules: HashMap::new(),
            resource_rules: vec![],
            taint_rules,
            created_at: None,
            protect_lethal_trifecta: false,
        }
    }

    fn taint_rule(tool: &str, action: &str) -> PolicyRule {
        PolicyRule {
            tool: Some(tool.to_string()),
            tool_class: None,
            action: action.to_string(),
            tag: if action == "ADD_TAINT" || action == "REMOVE_TAINT" {
                Some("TAG".to_string())
            } else {
                None
            },
            forbidden_tags: if action == "CHECK_TAINT" {
                Some(vec!["TAG".to_string()])
            } else {
                None
            },
            required_taints: None,
            error: None,
            pattern: None,
            exceptions: None,
        }
    }

    #[test]
    fn test_detailed_clean_policy_has_no_errors() {
        let policy = minimal_policy(vec![taint_rule("read_file", "ADD_TAINT")]);
        let diags = PolicyValidator::validate_policy_detailed(&policy);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == ValidationSeverity::Error)
            .collect();
        assert!(errors.is_empty(), "unexpected errors: {:?}", errors);
    }

    #[test]
    fn test_detailed_collects_all_errors_not_fail_fast() {
        // Two broken rules — both should appear in the output.
        let rule1 = PolicyRule {
            tool: None,
            tool_class: None, // error: missing both
            action: "ADD_TAINT".to_string(),
            tag: None, // error: ADD_TAINT needs tag
            forbidden_tags: None,
            required_taints: None,
            error: None,
            pattern: None,
            exceptions: None,
        };
        let rule2 = PolicyRule {
            tool: None,
            tool_class: None, // error: missing both
            action: "CHECK_TAINT".to_string(),
            tag: None,
            forbidden_tags: None, // error: CHECK_TAINT needs forbidden_tags
            required_taints: None,
            error: None,
            pattern: None,
            exceptions: None,
        };
        let policy = minimal_policy(vec![rule1, rule2]);
        let diags = PolicyValidator::validate_policy_detailed(&policy);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == ValidationSeverity::Error)
            .collect();
        // At minimum: missing tool×2, missing tag for ADD_TAINT, missing forbidden_tags for CHECK_TAINT
        assert!(errors.len() >= 4, "expected ≥4 errors, got {:?}", errors);
    }

    #[test]
    fn test_detailed_block_without_error_is_warning() {
        let rule = PolicyRule {
            tool: Some("my_tool".to_string()),
            tool_class: None,
            action: "BLOCK".to_string(),
            tag: None,
            forbidden_tags: None,
            required_taints: None,
            error: None, // missing → warning
            pattern: None,
            exceptions: None,
        };
        let policy = minimal_policy(vec![rule]);
        let diags = PolicyValidator::validate_policy_detailed(&policy);
        let warnings: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == ValidationSeverity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].field_path.contains("error"));
    }

    #[test]
    fn test_detailed_field_paths_are_structured() {
        let rule = PolicyRule {
            tool: None,
            tool_class: None,
            action: "INVALID_ACTION".to_string(),
            tag: None,
            forbidden_tags: None,
            required_taints: None,
            error: None,
            pattern: None,
            exceptions: None,
        };
        let policy = minimal_policy(vec![rule]);
        let diags = PolicyValidator::validate_policy_detailed(&policy);
        // All errors should reference taintRules[0]
        let has_indexed_path = diags
            .iter()
            .any(|d| d.field_path.starts_with("taintRules[0]"));
        assert!(has_indexed_path, "expected indexed path, got: {:?}", diags);
    }

    #[test]
    fn test_detailed_suggestions_present_on_errors() {
        let rule = PolicyRule {
            tool: Some("my_tool".to_string()),
            tool_class: None,
            action: "ADD_TAINT".to_string(),
            tag: None, // missing → should have suggestion
            forbidden_tags: None,
            required_taints: None,
            error: None,
            pattern: None,
            exceptions: None,
        };
        let policy = minimal_policy(vec![rule]);
        let diags = PolicyValidator::validate_policy_detailed(&policy);
        let errors_with_suggestion: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == ValidationSeverity::Error && d.suggestion.is_some())
            .collect();
        assert!(!errors_with_suggestion.is_empty());
    }
}
