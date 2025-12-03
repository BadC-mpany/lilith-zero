// YAML policy loading - Load policies.yaml with customer and policy definitions

use crate::core::errors::InterceptorError;
use crate::core::models::{CustomerConfig, PolicyDefinition};
use crate::utils::policy_validator::PolicyValidator;
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
#[derive(Clone)]
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

        // Validate all policies before returning
        let policy_list: Vec<_> = policies.values().cloned().collect();
        PolicyValidator::validate_policies(&policy_list)?;

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

    /// Validate that referenced policies exist and policy references are consistent
    pub fn validate(&self) -> Result<(), InterceptorError> {
        // Check that customers reference existing policies
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

        // Structural validation already done in from_file() via PolicyValidator
        Ok(())
    }

    /// Validate policies against known tool classes from tool registry
    pub fn validate_tool_classes(
        &self,
        known_classes: &std::collections::HashSet<String>,
    ) -> Result<(), InterceptorError> {
        let policy_list: Vec<_> = self.policies.values().cloned().collect();
        PolicyValidator::validate_tool_classes(&policy_list, known_classes)
    }
}
