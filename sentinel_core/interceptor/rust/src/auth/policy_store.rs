// Database-backed policy storage with YAML fallback

use crate::api::PolicyStore;
use crate::core::errors::InterceptorError;
use crate::core::models::PolicyDefinition;
use crate::loader::policy_loader::PolicyLoader;
use async_trait::async_trait;
use moka::future::Cache;
use sqlx::{PgPool, FromRow};
use std::sync::Arc;

/// Database row structure for policy lookup
#[derive(FromRow)]
struct PolicyRow {
    static_rules: serde_json::Value,
    taint_rules: serde_json::Value,
}

/// Database-backed policy store with in-memory caching
pub struct DbPolicyStore {
    db_pool: PgPool,
    cache: Cache<String, Arc<PolicyDefinition>>,
}

impl DbPolicyStore {
    /// Create a new database-backed policy store
    pub fn new(db_pool: PgPool) -> Self {
        let cache = Cache::builder()
            .time_to_live(std::time::Duration::from_secs(300)) // 5 minutes
            .max_capacity(100)
            .build();
        
        Self { db_pool, cache }
    }

    /// Load policy from database (internal method)
    pub async fn load_policy_internal(
        &self,
        policy_name: &str,
    ) -> Result<Option<Arc<PolicyDefinition>>, sqlx::Error> {
        // Check cache first
        if let Some(cached) = self.cache.get(policy_name).await {
            return Ok(Some(cached));
        }

        // Query database
        let row = sqlx::query_as::<_, PolicyRow>(
            "SELECT static_rules, taint_rules 
             FROM policies 
             WHERE name = $1"
        )
        .bind(policy_name)
        .fetch_optional(&self.db_pool)
        .await?;

        let policy = row.and_then(|r| {
            // Deserialize JSONB fields
            let static_rules: serde_json::Value = r.static_rules;
            let taint_rules: serde_json::Value = r.taint_rules;
            
            serde_json::from_value::<std::collections::HashMap<String, String>>(static_rules)
                .ok()
                .and_then(|static_rules| {
                    serde_json::from_value::<Vec<crate::core::models::PolicyRule>>(taint_rules)
                        .ok()
                        .map(|taint_rules| {
                            PolicyDefinition {
                                name: policy_name.to_string(),
                                static_rules,
                                taint_rules,
                            }
                        })
                })
        });

        // Cache if found
        if let Some(ref policy) = policy {
            let policy_arc = Arc::new(policy.clone());
            self.cache.insert(policy_name.to_string(), policy_arc.clone()).await;
            Ok(Some(policy_arc))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl PolicyStore for DbPolicyStore {
    async fn load_policy(
        &self,
        policy_name: &str,
    ) -> Result<Option<Arc<PolicyDefinition>>, InterceptorError> {
        self.load_policy_internal(policy_name)
            .await
            .map_err(|e| InterceptorError::StateError(format!("Database error: {}", e)))
    }
}

/// YAML fallback policy store (for MVP deployment without database)
pub struct YamlPolicyStore {
    policy_loader: PolicyLoader,
}

impl YamlPolicyStore {
    /// Create a new YAML-backed policy store
    pub fn new(policy_loader: PolicyLoader) -> Self {
        Self { policy_loader }
    }
}

#[async_trait]
impl PolicyStore for YamlPolicyStore {
    async fn load_policy(
        &self,
        policy_name: &str,
    ) -> Result<Option<Arc<PolicyDefinition>>, InterceptorError> {
        Ok(self.policy_loader.get_policy(policy_name).map(|p| Arc::new(p.clone())))
    }
}

/// Fallback policy store that tries database first, then YAML
pub struct FallbackPolicyStore {
    db_store: Option<Arc<DbPolicyStore>>,
    yaml_store: Option<Arc<YamlPolicyStore>>,
}

impl FallbackPolicyStore {
    /// Create a fallback store with database and/or YAML
    pub fn new(
        db_store: Option<Arc<DbPolicyStore>>,
        yaml_store: Option<Arc<YamlPolicyStore>>,
    ) -> Self {
        Self {
            db_store,
            yaml_store,
        }
    }
}

#[async_trait]
impl PolicyStore for FallbackPolicyStore {
    async fn load_policy(
        &self,
        policy_name: &str,
    ) -> Result<Option<Arc<PolicyDefinition>>, InterceptorError> {
        // Try database first if available
        if let Some(ref db_store) = self.db_store {
            match db_store.load_policy(policy_name).await {
                Ok(Some(policy)) => return Ok(Some(policy)),
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
        if let Some(ref yaml_store) = self.yaml_store {
            return yaml_store.load_policy(policy_name).await;
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::policy_loader::PolicyLoader;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_yaml_policy_store() {
        // Create a temporary YAML file
        let yaml_content = r#"
customers:
  - api_key: "test_key"
    owner: "test"
    mcp_upstream_url: "http://localhost:9000"
    policy_name: "test_policy"
policies:
  - name: "test_policy"
    static_rules:
      read_file: "ALLOW"
    taint_rules: []
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", yaml_content).unwrap();
        let path = temp_file.path();

        let loader = PolicyLoader::from_file(path).unwrap();
        let store = YamlPolicyStore::new(loader);

        let policy = store.load_policy("test_policy").await.unwrap();
        assert!(policy.is_some());
        let policy = policy.unwrap();
        assert_eq!(policy.name, "test_policy");
        assert!(policy.static_rules.contains_key("read_file"));
    }
}
