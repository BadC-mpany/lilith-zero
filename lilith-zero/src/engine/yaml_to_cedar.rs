// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::engine_core::models::{LogicCondition, LogicValue, PolicyDefinition};
use crate::engine_core::path_utils::lexical_canonicalize;
use cedar_policy::{Policy, PolicyId, PolicySet};
use std::str::FromStr;

/// Compiles a legacy YAML `PolicyDefinition` into a formally verified Cedar `PolicySet`.
pub struct CedarCompiler;

impl CedarCompiler {
    /// Compiles the given policy definition into a Cedar PolicySet.
    pub fn compile(def: &PolicyDefinition) -> Result<PolicySet, String> {
        let mut set = PolicySet::new();

        // 1. Static Rules
        // static_rules map a tool_name to "ALLOW" or "DENY"
        for (tool, action) in &def.static_rules {
            let policy_src = if action.eq_ignore_ascii_case("ALLOW") {
                format!(
                    r#"permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"{}"
);"#,
                    tool
                )
            } else {
                format!(
                    r#"@error("Blocked by static policy rule for tool: {}")
forbid(
    principal,
    action == Action::"tools/call",
    resource == Resource::"{}"
);"#,
                    tool, tool
                )
            };

            let policy = Policy::parse(
                Some(
                    PolicyId::from_str(&Self::sanitize_id(&format!("static_{}", tool)))
                        .expect("invariant: sanitize_id produces only [a-zA-Z0-9:_] chars"),
                ),
                &policy_src,
            )
            .map_err(|e| format!("Failed to compile static rule for {}: {}", tool, e))?;
            set.add(policy).map_err(|e| e.to_string())?;
        }

        // 2. Resource Rules (Ordered: First match wins)
        let mut previous_resource_patterns = Vec::new();

        for (i, rule) in def.resource_rules.iter().enumerate() {
            // Cedar's `like` operator uses `*` for wildcards.
            // We must canonicalize the pattern just like we do at runtime.
            let p = rule
                .uri_pattern
                .strip_prefix("file://")
                .unwrap_or(&rule.uri_pattern);
            let p = p.strip_prefix("file:").unwrap_or(p);
            let canon_pattern = lexical_canonicalize(p).to_string_lossy().to_string();

            let cedar_pattern = canon_pattern.replace("\\*", "*");

            let effect = if rule.action.eq_ignore_ascii_case("ALLOW") {
                "permit"
            } else {
                "forbid"
            };

            let mut annotations = String::new();
            if effect == "forbid" {
                annotations = format!(
                    r#"@error("Resource blocked by rule: {}")"#,
                    rule.uri_pattern
                );
            }

            // To support ordered "first match wins", this rule only matches if NO previous rule matched.
            let mut order_cond = String::new();
            if !previous_resource_patterns.is_empty() {
                order_cond = format!(" && !({})", previous_resource_patterns.join(" || "));
            }

            let policy_src = format!(
                r#"{}{} (
    principal,
    action == Action::"resources/read",
    resource
) when {{
    context.path like "{}"{}
}};"#,
                annotations, effect, cedar_pattern, order_cond
            );

            let policy = Policy::parse(
                Some(
                    PolicyId::from_str(&Self::sanitize_id(&format!("resource_rule_{}", i)))
                        .expect("invariant: sanitize_id produces only [a-zA-Z0-9:_] chars"),
                ),
                &policy_src,
            )
            .map_err(|e| format!("Failed to compile resource rule {}: {}", i, e))?;
            set.add(policy).map_err(|e| e.to_string())?;

            // 2b. Resource Taints (Side effects)
            if let Some(ref taints) = rule.taints_to_add {
                for (j, tag) in taints.iter().enumerate() {
                    let taint_policy_src = format!(
                        r#"permit(
    principal,
    action == Action::"resources/read",
    resource
) when {{
    context.path like "{}"{}
}};"#,
                        cedar_pattern, order_cond
                    );
                    let taint_policy = Policy::parse(
                        Some(
                            PolicyId::from_str(&Self::sanitize_id(&format!(
                                "add_taint:{}:res_{}_{}",
                                tag, i, j
                            )))
                            .expect("invariant: sanitize_id produces only [a-zA-Z0-9:_] chars"),
                        ),
                        &taint_policy_src,
                    )
                    .map_err(|e| format!("Failed to compile resource taint rule: {}", e))?;
                    set.add(taint_policy).map_err(|e| e.to_string())?;
                }
            }

            previous_resource_patterns.push(format!("context.path like \"{}\"", cedar_pattern));
        }

        // Add default permit for resources/read ONLY IF it wasn't matched by any previous rule
        let mut final_order_cond = String::new();
        if !previous_resource_patterns.is_empty() {
            final_order_cond = format!(" && !({})", previous_resource_patterns.join(" || "));
        }

        let default_resource_permit = Policy::parse(
            Some(
                PolicyId::from_str(&Self::sanitize_id("default_resource_permit"))
                    .expect("invariant: sanitize_id produces only [a-zA-Z0-9:_] chars"),
            ),
            format!(
                r#"permit(principal, action == Action::"resources/read", resource) when {{ true{} }};"#,
                final_order_cond
            ),
        )
        .map_err(|e| format!("Failed to compile default resource permit: {}", e))?;
        set.add(default_resource_permit)
            .map_err(|e| e.to_string())?;

        // 3. Taint Rules (Ordered: First match wins)
        let mut previous_taint_patterns = Vec::new();

        for (i, rule) in def.taint_rules.iter().enumerate() {
            let mut current_pattern;

            let resource_cond = if let Some(ref t) = rule.tool {
                current_pattern = format!("(resource == Resource::\"{}\")", t);
                format!("resource == Resource::\"{}\"", t)
            } else if let Some(ref tc) = rule.tool_class {
                current_pattern = format!("(context.classes.contains(\"{}\"))", tc);
                format!("context.classes.contains(\"{}\")", tc)
            } else {
                current_pattern = "true".to_string();
                "true".to_string()
            };

            let mut conditions = vec![];

            // Required Taints
            if let Some(ref req_taints) = rule.required_taints {
                for rt in req_taints {
                    conditions.push(format!("context.taints.contains(\"{}\")", rt));
                }
            }

            // Forbidden Taints
            if let Some(ref forbid_taints) = rule.forbidden_tags {
                for ft in forbid_taints {
                    conditions.push(format!("context.taints.contains(\"{}\")", ft));
                }
            }

            // Argument Matching (match_args)
            if let Some(ref match_args) = rule.match_args {
                if let Some(obj) = match_args.as_object() {
                    for (key, val) in obj {
                        if let Some(s) = val.as_str() {
                            let match_expr =
                                if s.contains('*') || s.contains('.') || s.contains('|') {
                                    let simplified = s.replace(".*", "*").replace(".+", "*");
                                    format!("context.args.{} like \"{}\"", key, simplified)
                                } else {
                                    format!("context.args.{} == \"{}\"", key, s)
                                };
                            conditions.push(match_expr.clone());
                            // Add to pattern for ordering
                            if current_pattern == "true" {
                                current_pattern = match_expr;
                            } else {
                                current_pattern =
                                    format!("({} && {})", current_pattern, match_expr);
                            }
                        }
                    }
                }
            }

            // Support full LogicCondition tree (pattern field)
            if let Some(ref pattern) = rule.pattern {
                let pattern_expr = Self::compile_condition(pattern)?;
                conditions.push(pattern_expr.clone());
                if current_pattern == "true" {
                    current_pattern = pattern_expr;
                } else {
                    current_pattern = format!("({} && {})", current_pattern, pattern_expr);
                }
            }

            // Ordering: Match if NO previous rule matched
            let mut order_cond = String::new();
            if !previous_taint_patterns.is_empty() {
                order_cond = format!(" && !({})", previous_taint_patterns.join(" || "));
            }

            // Tags for ADD/REMOVE
            let mut policy_id_prefix = "rule".to_string();
            let effect = match rule.action.to_uppercase().as_str() {
                "ALLOW" => "permit",
                "BLOCK" | "CHECK_TAINT" => "forbid",
                "ADD_TAINT" => {
                    policy_id_prefix = format!("add_taint:{}:", rule.tag.as_deref().unwrap_or(""));
                    "permit"
                }
                "REMOVE_TAINT" => {
                    policy_id_prefix =
                        format!("remove_taint:{}:", rule.tag.as_deref().unwrap_or(""));
                    "permit"
                }
                _ => "forbid", // Default to fail closed
            };

            let condition_str = if conditions.is_empty() {
                "".to_string()
            } else {
                format!(" && {}", conditions.join(" && "))
            };

            let mut annotations = String::new();
            if let Some(ref err) = rule.error {
                annotations = format!("@error(\"{}\")\n", err.replace("\"", "\\\""));
            }

            let policy_src = format!(
                r#"{}{} (
    principal,
    action == Action::"tools/call",
    resource
) when {{
    ({}){}{}{} 
}};"#,
                annotations, effect, resource_cond, condition_str, order_cond, ""
            );

            let policy = Policy::parse(
                Some(
                    PolicyId::from_str(&Self::sanitize_id(&format!("{}_{}", policy_id_prefix, i)))
                        .expect("invariant: sanitize_id produces only [a-zA-Z0-9:_] chars"),
                ),
                &policy_src,
            )
            .map_err(|e| format!("Failed to compile taint rule {}: {}", i, e))?;
            set.add(policy).map_err(|e| e.to_string())?;

            previous_taint_patterns.push(current_pattern);
        }

        Ok(set)
    }

    fn sanitize_id(id: &str) -> String {
        id.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == ':' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn compile_condition(cond: &LogicCondition) -> Result<String, String> {
        match cond {
            LogicCondition::And(inner) => {
                let parts: Result<Vec<_>, _> = inner.iter().map(Self::compile_condition).collect();
                Ok(format!("({})", parts?.join(" && ")))
            }
            LogicCondition::Or(inner) => {
                let parts: Result<Vec<_>, _> = inner.iter().map(Self::compile_condition).collect();
                Ok(format!("({})", parts?.join(" || ")))
            }
            LogicCondition::Not(inner) => Ok(format!("!{}", Self::compile_condition(inner)?)),
            LogicCondition::Eq(vals) => {
                if vals.len() != 2 {
                    return Err("Eq requires 2 values".to_string());
                }
                Ok(format!(
                    "{} == {}",
                    Self::compile_value(&vals[0])?,
                    Self::compile_value(&vals[1])?
                ))
            }
            LogicCondition::Neq(vals) => {
                if vals.len() != 2 {
                    return Err("Neq requires 2 values".to_string());
                }
                Ok(format!(
                    "{} != {}",
                    Self::compile_value(&vals[0])?,
                    Self::compile_value(&vals[1])?
                ))
            }
            LogicCondition::ToolArgsMatch(v) => {
                let mut matches = vec![];
                if let Some(obj) = v.as_object() {
                    for (k, val) in obj {
                        if let Some(s) = val.as_str() {
                            if s.contains('*') {
                                let simplified = s.replace(".*", "*").replace(".+", "*");
                                matches.push(format!("context.args.{} like \"{}\"", k, simplified));
                            } else {
                                matches.push(format!("context.args.{} == \"{}\"", k, s));
                            }
                        }
                    }
                }
                if matches.is_empty() {
                    Ok("true".to_string())
                } else {
                    Ok(format!("({})", matches.join(" && ")))
                }
            }
            _ => Ok("false".to_string()),
        }
    }

    fn compile_value(val: &LogicValue) -> Result<String, String> {
        match val {
            LogicValue::Str(s) => Ok(format!("\"{}\"", s)),
            LogicValue::Num(n) => Ok(n.to_string()),
            LogicValue::Var { var } => Ok(format!("context.args.{}", var)),
            _ => Err("Unsupported logic value".to_string()),
        }
    }
}
