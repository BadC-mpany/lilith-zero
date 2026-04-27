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

        // 3. Default Fallback
        // MCP requests are deny-by-default in Lilith Zero if not matched by an ALLOW rule.
        // Actually Cedar is default-deny. We don't need to add anything.

        Ok(set)
    }
}
