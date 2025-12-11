use crate::api::{CustomerStore, PolicyStore};
use crate::core::errors::InterceptorError;
use crate::core::models::{CustomerConfig, PolicyDefinition};
use crate::infra::supabase::SupabaseClient;
use async_trait::async_trait;
use std::sync::Arc;
use moka::future::Cache;
use tokio::sync::RwLock;
use std::collections::HashMap;
use tracing::{debug, error};

/// Supabase-backed store that combines Customer and Policy lookups
/// Policies are embedded in the Project configuration in Supabase.
pub struct SupabaseStore {
    client: Arc<SupabaseClient>,
    // Cache for Project/Customer Config
    customer_cache: Cache<String, Arc<CustomerConfig>>,
    // Cache for Policies (keyed by policy name)
    // Since policies are scoped to projects in JSON, we rely on the flow
    // lookup_customer -> load_policy to populate this cache.
    policy_cache: RwLock<HashMap<String, Arc<PolicyDefinition>>>,
}

impl SupabaseStore {
    pub fn new(client: Arc<SupabaseClient>) -> Self {
        Self {
            client,
            customer_cache: Cache::builder()
                .time_to_live(std::time::Duration::from_secs(300))
                .build(),
            policy_cache: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl CustomerStore for SupabaseStore {
    async fn lookup_customer(&self, api_key_hash: &str) -> Result<Option<CustomerConfig>, InterceptorError> {
        // 1. Check Cache
        if let Some(cached) = self.customer_cache.get(api_key_hash).await {
            return Ok(Some((*cached).clone()));
        }

        // 2. Fetch from Supabase
        // Note: We use the hash as the API key lookup value, assuming DB stores hashes.
        let project = self.client.get_project_config(api_key_hash).await;
        
        match project {
            Ok(proj) => {
                // Map to CustomerConfig
                // We pick the first policy name as the active one?
                // Or user schema `policies` is a list, and `projects` table provided `policies` JSON.
                // The provided schema has `policies` list in JSON. 
                // We need to decide which policy is "active". 
                // Let's assume the first policy in the list is the default one, or we use a convention.
                // User Example: `policies` in SQL has one entry: `{"name": "", ...}`. Name is empty string?
                // The `CustomerConfig` needs `policy_name`.
                // Let's use the first policy's name.
                
                let active_policy = proj.policies.first().ok_or_else(|| 
                    InterceptorError::ConfigurationError("Project has no policies".to_string())
                )?;
                
                let policy_name = if active_policy.name.is_empty() {
                    "default".to_string() 
                } else {
                    active_policy.name.clone()
                };

                let config = CustomerConfig {
                    owner: proj.id.clone(), // Use Project ID as owner for now
                    mcp_upstream_url: std::env::var("MCP_UPSTREAM_URL").unwrap_or_else(|_| "http://localhost:9000".to_string()),
                    // User Request Schema: "id", "user_id", "name", "description", "tools", "policies", "api_key", ...
                    // It does NOT have mcp_upstream_url.
                    // I will default it or look for it in description? 
                    // Let's default to env var or fixed value for now to unblock.
                    policy_name: policy_name.clone(),
                };

                // STORE POLICIES IN CACHE
                {
                    let mut cache = self.policy_cache.write().await;
                    for mut p in proj.policies {
                        if p.name.is_empty() { p.name = "default".to_string(); }
                        cache.insert(p.name.clone(), Arc::new(p));
                    }
                }

                // Cache Customer
                let config_arc = Arc::new(config.clone());
                self.customer_cache.insert(api_key_hash.to_string(), config_arc).await;

                Ok(Some(config))
            }
            // If error is specific to "Not Found", return None?
            // SupabaseClient returns Error if not found.
            Err(InterceptorError::AuthenticationError(_)) => {
                debug!("Supabase: Project not found or invalid key for key: {}", api_key_hash);
                Ok(None)
            },
            Err(e) => {
                error!(error = %e, "Supabase lookup failed");
                Err(e)
            },
        }
    }
}

#[async_trait]
impl PolicyStore for SupabaseStore {
    async fn load_policy(&self, policy_name: &str) -> Result<Option<Arc<PolicyDefinition>>, InterceptorError> {
        let cache = self.policy_cache.read().await;
        Ok(cache.get(policy_name).cloned())
    }
}
