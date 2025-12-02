// Tool registry loading - Maps tool names to security classes

use crate::core::errors::InterceptorError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Tool definition from tool_registry.yaml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub description: String,
    pub classes: Vec<String>,
    #[serde(default)]
    pub auto_classified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<HashMap<String, serde_json::Value>>,
}

/// Container for tool registry YAML structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolRegistryYaml {
    tools: HashMap<String, ToolDefinition>,
}

/// Tool registry loader - provides tool name to security classes mapping
pub struct ToolRegistry {
    tools: HashMap<String, ToolDefinition>,
}

impl ToolRegistry {
    /// Load tool registry from YAML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, InterceptorError> {
        let path_ref = path.as_ref();
        
        if !path_ref.exists() {
            return Err(InterceptorError::ConfigurationError(
                format!("Tool registry not found at {:?}", path_ref)
            ));
        }

        let yaml_content = fs::read_to_string(path_ref)
            .map_err(|e| InterceptorError::ConfigurationError(
                format!("Failed to read tool registry: {}", e)
            ))?;

        let registry: ToolRegistryYaml = serde_yaml::from_str(&yaml_content)
            .map_err(|e| InterceptorError::ConfigurationError(
                format!("Failed to parse tool registry YAML: {}", e)
            ))?;

        Ok(Self {
            tools: registry.tools,
        })
    }

    /// Get security classes for a tool
    /// Returns empty Vec if tool not found (matches Python behavior)
    pub fn get_tool_classes(&self, tool_name: &str) -> Vec<String> {
        self.tools
            .get(tool_name)
            .map(|tool_def| tool_def.classes.clone())
            .unwrap_or_default()
    }

    /// Check if a tool exists in the registry
    pub fn tool_exists(&self, tool_name: &str) -> bool {
        self.tools.contains_key(tool_name)
    }

    /// Get tool definition (for future use)
    pub fn get_tool_definition(&self, tool_name: &str) -> Option<&ToolDefinition> {
        self.tools.get(tool_name)
    }

    /// Get all tool names
    pub fn get_all_tool_names(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }
}
