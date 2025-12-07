// Adapter to bridge API trait (async, String errors) and engine implementation (async, InterceptorError)

use crate::api::{PolicyEvaluator as ApiPolicyEvaluator, RedisStore};
use crate::core::models::{Decision, PolicyDefinition};
use crate::core::errors::InterceptorError;
use crate::engine::evaluator::PolicyEvaluator as EnginePolicyEvaluator;
use std::collections::HashSet;
use std::sync::Arc;
use tracing;

/// Adapter that bridges the async API trait with the async engine implementation
/// 
/// This adapter:
/// - Fetches session history from Redis
/// - Converts Vec<String> taints to HashSet<String>
/// - Maps InterceptorError to String for trait compatibility
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
    ) -> Result<Decision, InterceptorError> {
        // Fetch session history from Redis
        // CRITICAL: Redis timeout should not block policy evaluation but failing closed
        // Use 2-second timeout to match handler timeout for fast-fail
        use tokio::time::{timeout, Duration};
        let history = match timeout(
            Duration::from_secs(2),
            self.redis_store.get_session_history(session_id)
        ).await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                tracing::error!(
                    error = %e,
                    session_id = session_id,
                    "Failed to fetch session history - failing closed"
                );
                return Err(e);
            }
            Err(_) => {
                tracing::error!(
                    session_id = session_id,
                    "Session history fetch timed out after 2 seconds - failing closed"
                );
                return Err(InterceptorError::StateError("Session history fetch timed out".to_string()));
            }
        };

        // Convert Vec<String> to HashSet<String> for engine
        let taints_set: HashSet<String> = session_taints.iter().cloned().collect();

        // Call async engine - engine handles the actual policy evaluation
        EnginePolicyEvaluator::evaluate(
            policy,
            tool_name,
            tool_classes,
            &history,
            &taints_set,
        )
        .await
        .map_err(|e| InterceptorError::StateError(format!("Engine evaluation error: {}", e)))
    }
}
