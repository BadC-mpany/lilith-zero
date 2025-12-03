// Moka cache for policies

use crate::api::{PolicyCache, PolicyStore};
use crate::core::models::PolicyDefinition;
use async_trait::async_trait;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

/// Moka-based policy cache implementation
/// 
/// Provides in-memory caching of policies with TTL expiration.
/// Cache misses are automatically loaded from the underlying PolicyStore.
pub struct MokaPolicyCache {
    cache: Cache<String, Arc<PolicyDefinition>>,
    policy_store: Arc<dyn PolicyStore + Send + Sync>,
}

impl MokaPolicyCache {
    /// Create a new MokaPolicyCache with the given policy store
    /// 
    /// # Parameters
    /// * `policy_store` - The underlying policy store for cache misses
    /// * `ttl_secs` - Time-to-live for cached policies in seconds (default: 60)
    /// * `max_capacity` - Maximum number of policies to cache (default: 1000)
    pub fn new(
        policy_store: Arc<dyn PolicyStore + Send + Sync>,
        ttl_secs: u64,
        max_capacity: u64,
    ) -> Self {
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(ttl_secs))
            .max_capacity(max_capacity)
            .build();
        
        Self {
            cache,
            policy_store,
        }
    }
}

#[async_trait]
impl PolicyCache for MokaPolicyCache {
    async fn get_policy(&self, policy_name: &str) -> Result<Option<Arc<PolicyDefinition>>, String> {
        // Try cache first
        if let Some(policy) = self.cache.get(policy_name).await {
            return Ok(Some(policy));
        }
        
        // Cache miss: load from store
        match self.policy_store.load_policy(policy_name).await {
            Ok(Some(policy)) => {
                // Cache the policy for future use
                let policy_clone = Arc::clone(&policy);
                self.cache.insert(policy_name.to_string(), policy_clone).await;
                Ok(Some(policy))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
    
    async fn put_policy(&self, policy_name: &str, policy: Arc<PolicyDefinition>) -> Result<(), String> {
        self.cache.insert(policy_name.to_string(), policy).await;
        Ok(())
    }
}
