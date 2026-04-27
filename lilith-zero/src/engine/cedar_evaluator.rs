// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, RestrictedExpression};
use std::collections::HashSet;
use std::str::FromStr;
use serde_json::Value;

use crate::engine_core::errors::InterceptorError;

/// A Cedar-based policy evaluator.
/// Instead of interpreting a YAML AST, it uses the formally verified Cedar language.
pub struct CedarEvaluator {
    authorizer: Authorizer,
    policy_set: PolicySet,
}

impl CedarEvaluator {
    pub fn new(policy_set: PolicySet) -> Self {
        Self {
            authorizer: Authorizer::new(),
            policy_set,
        }
    }

    /// Evaluate an MCP action for a given session.
    pub fn evaluate(
        &self,
        session_id: &str,
        action: &str,
        resource: &str,
        tool_args: &Value,
        canonical_paths: &[String],
        taints: &HashSet<String>,
    ) -> Result<Decision, InterceptorError> {
        // Principal is the session (or agent)
        let principal = EntityUid::from_str(&format!(r#"Session::"{}""#, session_id))
            .map_err(|e| InterceptorError::InternalError(format!("Invalid Principal UID: {}", e)))?;

        // Action is the MCP method (e.g., tools/call, resources/read)
        let action_uid = EntityUid::from_str(&format!(r#"Action::"{}""#, action))
            .map_err(|e| InterceptorError::InternalError(format!("Invalid Action UID: {}", e)))?;

        // Resource is the tool name or the resource URI
        let resource_uid = EntityUid::from_str(&format!(r#"Resource::"{}""#, resource))
            .map_err(|e| InterceptorError::InternalError(format!("Invalid Resource UID: {}", e)))?;

        // Context contains active taints, safe paths, and original args (for reference, though typed schemas are better)
        let taints_list: Vec<Value> = taints.iter().map(|t| Value::String(t.clone())).collect();
        let paths_list: Vec<Value> = canonical_paths.iter().map(|p| Value::String(p.clone())).collect();

        // Serialize Context to JSON 
        let context_json = serde_json::json!({
            "taints": taints_list,
            "paths": paths_list,
            "args": tool_args
        });

        let context = Context::from_json_value(context_json, None)
            .map_err(|e| InterceptorError::InternalError(format!("Context conversion failed: {}", e)))?;

        let request = Request::new(principal, action_uid, resource_uid, context, None)
            .map_err(|e| InterceptorError::InternalError(format!("Request construction failed: {}", e)))?;

        let entities = Entities::empty();

        let response = self.authorizer.is_authorized(&request, &self.policy_set, &entities);

        Ok(response.decision())
    }
}
