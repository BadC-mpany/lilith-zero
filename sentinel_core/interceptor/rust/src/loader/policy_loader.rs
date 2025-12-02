// YAML policy loading - Load policies.yaml with customer and policy definitions

use crate::core::errors::InterceptorError;
use crate::core::models::{CustomerConfig, PolicyDefinition};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Container for policies.yaml root structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PoliciesYaml {
    customers: Vec<CustomerEntry>,
    policies: Vec<PolicyDefinition>,
}

/// Customer entry with API key
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CustomerEntry {
    api_key: String,
    owner: String,
    mcp_upstream_url: String,
    policy_name: String,
}

/// Policy loader - manages customer and policy configurations
pub struct PolicyLoader {
    /// Map API key -> CustomerConfig
    customers: HashMap<String, CustomerConfig>,
    /// Map policy name -> PolicyDefinition
    policies: HashMap<String, PolicyDefinition>,
}

impl PolicyLoader {
    /// Load policies from YAML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, InterceptorError> {
        let path_ref = path.as_ref();
        
        if !path_ref.exists() {
            return Err(InterceptorError::ConfigurationError(
                format!("Policies file not found at {:?}", path_ref)
            ));
        }

        let yaml_content = fs::read_to_string(path_ref)
            .map_err(|e| InterceptorError::ConfigurationError(
                format!("Failed to read policies file: {}", e)
            ))?;

        let policies_yaml: PoliciesYaml = serde_yaml::from_str(&yaml_content)
            .map_err(|e| InterceptorError::ConfigurationError(
                format!("Failed to parse policies YAML: {}", e)
            ))?;

        // Build customer map
        let mut customers = HashMap::new();
        for entry in policies_yaml.customers {
            let config = CustomerConfig {
                owner: entry.owner,
                mcp_upstream_url: entry.mcp_upstream_url,
                policy_name: entry.policy_name,
            };
            customers.insert(entry.api_key, config);
        }

        // Build policy map
        let mut policies = HashMap::new();
        for policy in policies_yaml.policies {
            policies.insert(policy.name.clone(), policy);
        }

        Ok(Self { customers, policies })
    }

    /// Get customer configuration by API key
    pub fn get_customer_config(&self, api_key: &str) -> Option<&CustomerConfig> {
        self.customers.get(api_key)
    }

    /// Get policy definition by name
    pub fn get_policy(&self, policy_name: &str) -> Option<&PolicyDefinition> {
        self.policies.get(policy_name)
    }

    /// Validate that referenced policies exist
    pub fn validate(&self) -> Result<(), InterceptorError> {
        for (api_key, customer) in &self.customers {
            if !self.policies.contains_key(&customer.policy_name) {
                return Err(InterceptorError::ConfigurationError(
                    format!(
                        "Customer with API key '{}' references non-existent policy '{}'",
                        api_key, customer.policy_name
                    )
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_loader() {
        // Test with actual policies.yaml
        let loader = PolicyLoader::from_file("../../../policies.yaml");
        
        if let Ok(loader) = loader {
            // Test customer lookup
            let customer = loader.get_customer_config("sk_live_demo_123");
            assert!(customer.is_some());
            
            if let Some(customer) = customer {
                assert_eq!(customer.owner, "Demo User");
                assert_eq!(customer.policy_name, "default_policy");
            }

            // Test policy lookup
            let policy = loader.get_policy("default_policy");
            assert!(policy.is_some());

            // Test validation
            assert!(loader.validate().is_ok());
        }
    }
}
