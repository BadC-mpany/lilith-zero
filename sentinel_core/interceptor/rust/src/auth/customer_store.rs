// Database-backed customer storage with YAML fallback

use crate::api::CustomerStore;
use crate::auth::api_key::ApiKeyHash;
use crate::core::models::CustomerConfig;
use crate::loader::policy_loader::PolicyLoader;
use async_trait::async_trait;
use moka::future::Cache;
use sqlx::{PgPool, FromRow};
use std::sync::Arc;

/// Database row structure for customer lookup
#[derive(FromRow)]
struct CustomerRow {
    owner: String,
    mcp_upstream_url: String,
    policy_name: String,
}

/// Database-backed customer store with in-memory caching
pub struct DbCustomerStore {
    db_pool: PgPool,
    cache: Cache<String, Arc<CustomerConfig>>,
}

impl DbCustomerStore {
    /// Create a new database-backed customer store
    pub fn new(db_pool: PgPool) -> Self {
        let cache = Cache::builder()
            .time_to_live(std::time::Duration::from_secs(300)) // 5 minutes
            .max_capacity(1000)
            .build();
        
        Self { db_pool, cache }
    }

    /// Lookup customer by API key hash (internal method)
    pub async fn lookup_customer_by_hash(
        &self,
        api_key_hash: &ApiKeyHash,
    ) -> Result<Option<CustomerConfig>, sqlx::Error> {
        // Check cache first
        if let Some(cached) = self.cache.get(api_key_hash.as_str()).await {
            return Ok(Some((*cached).clone()));
        }

        // Query database
        let row = sqlx::query_as::<_, CustomerRow>(
            "SELECT owner, mcp_upstream_url, policy_name 
             FROM customers 
             WHERE api_key_hash = $1 AND revoked_at IS NULL"
        )
        .bind(api_key_hash.as_str())
        .fetch_optional(&self.db_pool)
        .await?;

        let customer = row.map(|r| CustomerConfig {
            owner: r.owner,
            mcp_upstream_url: r.mcp_upstream_url,
            policy_name: r.policy_name,
        });

        // Cache if found
        if let Some(ref config) = customer {
            self.cache
                .insert(
                    api_key_hash.as_str().to_string(),
                    Arc::new(config.clone()),
                )
                .await;
        }

        Ok(customer)
    }
}

#[async_trait]
impl CustomerStore for DbCustomerStore {
    async fn lookup_customer(
        &self,
        api_key_hash: &str,
    ) -> Result<Option<CustomerConfig>, String> {
        // api_key_hash is already a hash string (64 hex chars), not a plaintext key
        // Use from_hash_string to avoid double-hashing
        let hash = ApiKeyHash::from_hash_string(api_key_hash)
            .map_err(|e| format!("Invalid hash format: {}", e))?;
        self.lookup_customer_by_hash(&hash)
            .await
            .map_err(|e| format!("Database error: {}", e))
    }
}

/// YAML fallback customer store (for MVP deployment without database)
pub struct YamlCustomerStore {
    policy_loader: PolicyLoader,
}

impl YamlCustomerStore {
    /// Create a new YAML-backed customer store
    pub fn new(policy_loader: PolicyLoader) -> Self {
        Self { policy_loader }
    }

    /// Lookup customer by plaintext API key (YAML uses plaintext keys)
    pub fn lookup_customer_by_key(
        &self,
        api_key: &str,
    ) -> Option<CustomerConfig> {
        self.policy_loader.get_customer_config(api_key).cloned()
    }
}

#[async_trait]
impl CustomerStore for YamlCustomerStore {
    async fn lookup_customer(
        &self,
        _api_key_hash: &str,
    ) -> Result<Option<CustomerConfig>, String> {
        // Note: YAML store uses plaintext API keys, not hashes
        // This is a limitation of the MVP fallback approach
        // In production, database store should be used which stores hashes
        Err("YAML store requires plaintext API key, not hash".to_string())
    }
}

/// Fallback customer store that tries database first, then YAML
pub struct FallbackCustomerStore {
    db_store: Option<Arc<DbCustomerStore>>,
    yaml_store: Option<Arc<YamlCustomerStore>>,
}

impl FallbackCustomerStore {
    /// Create a fallback store with database and/or YAML
    pub fn new(
        db_store: Option<Arc<DbCustomerStore>>,
        yaml_store: Option<Arc<YamlCustomerStore>>,
    ) -> Self {
        Self {
            db_store,
            yaml_store,
        }
    }
}

#[async_trait]
impl CustomerStore for FallbackCustomerStore {
    async fn lookup_customer(
        &self,
        api_key_hash: &str,
    ) -> Result<Option<CustomerConfig>, String> {
        // Try database first if available
        if let Some(ref db_store) = self.db_store {
            match db_store.lookup_customer(api_key_hash).await {
                Ok(Some(config)) => return Ok(Some(config)),
                Ok(None) => {} // Not found in DB, try YAML
                Err(e) => {
                    // Database error, try YAML fallback
                    if self.yaml_store.is_some() {
                        // Fall through to YAML
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        // Try YAML fallback if available
        // Note: YAML store needs plaintext key, but we only have hash
        // This is a known limitation - YAML fallback requires different lookup method
        if let Some(_yaml_store) = &self.yaml_store {
            // Cannot lookup by hash in YAML store
            // This would require storing original API key temporarily or
            // using a different authentication flow for YAML mode
            return Err("YAML fallback requires plaintext API key lookup".to_string());
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::policy_loader::PolicyLoader;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[tokio::test]
    async fn test_yaml_customer_store() {
        // Create a temporary YAML file
        let yaml_content = r#"
customers:
  - api_key: "test_key_123"
    owner: "test_owner"
    mcp_upstream_url: "http://localhost:9000"
    policy_name: "test_policy"
policies:
  - name: "test_policy"
    static_rules: {}
    taint_rules: []
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", yaml_content).unwrap();
        let path = temp_file.path();

        let loader = PolicyLoader::from_file(path).unwrap();
        let store = YamlCustomerStore::new(loader);

        let config = store.lookup_customer_by_key("test_key_123");
        assert!(config.is_some());
        let config = config.unwrap();
        assert_eq!(config.owner, "test_owner");
        assert_eq!(config.mcp_upstream_url, "http://localhost:9000");
        assert_eq!(config.policy_name, "test_policy");
    }
}
