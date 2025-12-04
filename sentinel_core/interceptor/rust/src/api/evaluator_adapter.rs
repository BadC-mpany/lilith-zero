// Adapter to bridge API trait (async, String errors) and engine implementation (sync, InterceptorError)

use crate::api::{PolicyEvaluator as ApiPolicyEvaluator, RedisStore};
use crate::core::models::{Decision, PolicyDefinition};
use crate::engine::evaluator::PolicyEvaluator as EnginePolicyEvaluator;
use std::collections::HashSet;
use std::sync::Arc;
use tracing;

/// Adapter that bridges the async API trait with the sync engine implementation
/// 
/// This adapter:
/// - Fetches session history from Redis
/// - Converts Vec<String> taints to HashSet<String>
/// - Maps InterceptorError to String for trait compatibility
/// - Handles the async/sync boundary
pub struct PolicyEvaluatorAdapter {
    redis_store: Arc<dyn RedisStore + Send + Sync>,
}

impl PolicyEvaluatorAdapter {
    /// Create a new PolicyEvaluatorAdapter with a Redis store
    pub fn new(redis_store: Arc<dyn RedisStore + Send + Sync>) -> Self {
        Self { redis_store }
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
        session_id: &str,
    ) -> Result<Decision, String> {
        // Fetch session history from Redis (fail-safe: use empty history on timeout/error)
        // CRITICAL: Redis timeout should not block policy evaluation
        // If Redis is unavailable, proceed with empty history (fail-safe mode)
        let history = match self
            .redis_store
            .get_session_history(session_id)
            .await
        {
            Ok(h) => h,
            Err(e) => {
                // Log warning but proceed with empty history (fail-safe)
                tracing::warn!(
                    error = %e,
                    session_id = session_id,
                    "Failed to fetch session history - proceeding with empty history (fail-safe mode)"
                );
                Vec::new() // Fail-safe: empty history allows policy evaluation to proceed
            }
        };

        // Convert Vec<String> to HashSet<String> for engine
        let taints_set: HashSet<String> = session_taints.iter().cloned().collect();

        // Call engine (sync) - engine handles the actual policy evaluation
        EnginePolicyEvaluator::evaluate(
            policy,
            tool_name,
            tool_classes,
            &history,
            &taints_set,
        )
        .map_err(|e| e.to_string())
    }
}

