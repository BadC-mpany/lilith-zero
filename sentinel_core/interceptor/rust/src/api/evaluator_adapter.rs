// Adapter to bridge API trait (async, String errors) and engine implementation (async, InterceptorError)

use crate::api::PolicyEvaluator as ApiPolicyEvaluator;
use crate::core::models::{Decision, PolicyDefinition};
use crate::core::errors::InterceptorError;
use crate::engine::evaluator::PolicyEvaluator as EnginePolicyEvaluator;
use std::collections::HashSet;

/// Adapter that bridges the async API trait with the async engine implementation
/// 
/// This adapter:
/// - Converts Vec<String> taints to HashSet<String>
/// - Delegates to EnginePolicyEvaluator
pub struct PolicyEvaluatorAdapter;

impl PolicyEvaluatorAdapter {
    /// Create a new PolicyEvaluatorAdapter
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ApiPolicyEvaluator for PolicyEvaluatorAdapter {
    async fn evaluate(
        &self,
        policy: &PolicyDefinition,
        tool_name: &str,
        tool_classes: &[String],
        session_taints: &[String],
        session_history: &[crate::core::models::HistoryEntry],
        _session_id: &str,
    ) -> Result<Decision, InterceptorError> {
        // Convert Vec<String> to HashSet<String> for engine
        let taints_set: HashSet<String> = session_taints.iter().cloned().collect();

        // Call async engine - engine handles the actual policy evaluation
        EnginePolicyEvaluator::evaluate(
            policy,
            tool_name,
            tool_classes,
            session_history,
            &taints_set,
        )
        .await
        .map_err(|e| InterceptorError::StateError(format!("Engine evaluation error: {}", e)))
    }
}
