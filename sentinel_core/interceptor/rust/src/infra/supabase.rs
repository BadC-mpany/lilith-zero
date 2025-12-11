use crate::core::models::{PolicyDefinition, ToolConfig};
use crate::core::errors::InterceptorError;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::time::Duration;
use tracing::{info, error};

// ToolConfig moved to core::models

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub id: String,
    pub name: String,
    pub api_key: String,
    // policies and tools are stored as JSONB in DB, so we deserialize them directly
    #[serde(default)]
    pub policies: Vec<PolicyDefinition>,
    #[serde(default)]
    pub tools: Vec<ToolConfig>,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
}

#[derive(Clone)]
pub struct SupabaseClient {
    client: Client,
    project_url: String,
    service_role_key: String,
}

impl SupabaseClient {
    pub fn new(project_url: String, service_role_key: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| Client::new());

        let project_url = project_url.trim_end_matches('/').to_string();

        Self {
            client,
            project_url,
            service_role_key,
        }
    }

    /// Fetch project configuration by API Key (Exact Match)
    /// We assume the DB has a column `api_key` that we can filter on.
    /// In a real-world scenario with hashed keys, we would hash the input key 
    /// and search by the hash. Here we follow the straightforward "lookup" approach.
    pub async fn get_project_config(&self, api_key: &str) -> Result<ProjectConfig, InterceptorError> {
        let url = format!("{}/rest/v1/projects?api_key=eq.{}&select=*", self.project_url, api_key);
        
        let start_index = api_key.len().saturating_sub(4);
        info!("Fetching project config from Supabase for key ending in ...{}", &api_key[start_index..]);

        let response = self.client.get(&url)
            .header("apikey", &self.service_role_key)
            .header("Authorization", format!("Bearer {}", self.service_role_key))
            .send()
            .await
            .map_err(|e| InterceptorError::InfrastructureError(format!("Supabase request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            error!("Supabase error: {} - {}", status, text);
            return Err(InterceptorError::InfrastructureError(format!("Supabase HTTP error: {}", status)));
        }

        let projects: Vec<ProjectConfig> = response.json()
            .await
            .map_err(|e| InterceptorError::InfrastructureError(format!("Failed to deserialize project config: {}", e)))?;

        projects.into_iter().next()
            .ok_or_else(|| InterceptorError::AuthenticationError("Invalid API Key".to_string()))
    }
}
