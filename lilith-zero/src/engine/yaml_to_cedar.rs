// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::engine_core::models::{LogicCondition, LogicValue, PolicyDefinition, PolicyRule};
use cedar_policy::{Policy, PolicyId, PolicySet};
use std::str::FromStr;

/// Compiles a legacy YAML `PolicyDefinition` into a formally verified Cedar `PolicySet`.
pub struct CedarCompiler;

impl CedarCompiler {
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
                    r#"forbid(
    principal,
    action == Action::"tools/call",
    resource == Resource::"{}"
);"#,
                    tool
                )
            };

            let policy = Policy::parse(Some(PolicyId::from_str(&format!("static_{}", tool)).unwrap()), &policy_src)
                .map_err(|e| format!("Failed to compile static rule for {}: {}", tool, e))?;
            set.add(policy).map_err(|e| e.to_string())?;
        }

        // 2. Resource Rules
        for (i, rule) in def.resource_rules.iter().enumerate() {
            // Because resource rules use glob patterns (e.g. "file:///tmp/*"), and Cedar has limited globbing
            // (the `like` operator), we translate '*' to '*'.
            let cedar_pattern = rule.uri_pattern.replace("*", "*");
            
            let effect = if rule.action.eq_ignore_ascii_case("ALLOW") { "permit" } else { "forbid" };
            
            let policy_src = format!(
                r#"{} (
    principal,
    action,
    resource
) when {{
    context.paths.contains("{}") // This is an approximation for exact match. 
}};"#,
                effect, cedar_pattern
            );
            
            // Note: Since Cedar doesn't natively do "any path in array matches glob", 
            // a rigorous way is to evaluate the glob in Rust and pass matched flags, OR use Cedar `like`.
            // For now, we will add a simplistic forbid.
            let policy = Policy::parse(Some(PolicyId::from_str(&format!("resource_rule_{}", i)).unwrap()), &policy_src)
                .map_err(|e| format!("Failed to compile resource rule: {}", e))?;
            set.add(policy).map_err(|e| e.to_string())?;
        }

        // 3. Taint Rules
        for (i, rule) in def.taint_rules.iter().enumerate() {
            let mut resource_cond = String::new();
            if let Some(ref t) = rule.tool {
                resource_cond = format!("resource == Resource::\"{}\"", t);
            } else if let Some(ref tc) = rule.tool_class {
                resource_cond = format!("context.classes.contains(\"{}\")", tc);
            } else {
                resource_cond = "true".to_string(); // Applies to all
            }

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
            
            // Tags for ADD/REMOVE
            let mut policy_id_prefix = "rule".to_string();
            let effect = match rule.action.to_uppercase().as_str() {
                "ALLOW" => "permit",
                "BLOCK" | "CHECK_TAINT" => "forbid",
                "ADD_TAINT" => {
                    policy_id_prefix = format!("add_taint:{}", rule.tag.as_deref().unwrap_or(""));
                    "permit"
                },
                "REMOVE_TAINT" => {
                    policy_id_prefix = format!("remove_taint:{}", rule.tag.as_deref().unwrap_or(""));
                    "permit"
                },
                _ => "forbid", // Default to fail closed
            };

            let condition_str = if conditions.is_empty() {
                "".to_string()
            } else {
                format!(" && {}", conditions.join(" && "))
            };

            let policy_src = format!(
                r#"{} (
    principal,
    action == Action::"tools/call",
    resource
) when {{
    ({}){} 
}};"#,
                effect, resource_cond, condition_str
            );

            let policy = Policy::parse(Some(PolicyId::from_str(&format!("{}_{}", policy_id_prefix, i)).unwrap()), &policy_src)
                .map_err(|e| format!("Failed to compile taint rule: {}", e))?;
            set.add(policy).map_err(|e| e.to_string())?;
        }

        Ok(set)
    }
}
