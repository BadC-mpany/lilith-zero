// Supabase-based tool registry implementation

use crate::core::errors::InterceptorError;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Tool registry that caches tool metadata from Supabase
/// 
/// Tools are stored in the `projects.tools` JSON column in Supabase.
/// Each tool has a `taint_class` field that defines its security classification.
/// 
/// This implementation caches tool metadata in memory to avoid repeated lookups.
/// The cache is populated during session initialization when tools are loaded from Supabase.
pub struct SupabaseToolRegistry {
    /// Cache: tool_name -> classes
    cache: RwLock<HashMap<String, Vec<String>>>,
}

impl SupabaseToolRegistry {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Get tool classes for a given tool name
    /// 
    /// First checks the cache, then falls back to fetching from Supabase.
    /// Note: This requires an API key to fetch the project config.
    /// In practice, tools are already cached in Redis during session init,
    /// so this is mainly a fallback.
    pub async fn get_tool_classes(&self, tool_name: &str) -> Result<Vec<String>, InterceptorError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(classes) = cache.get(tool_name) {
                return Ok(classes.clone());
            }
        }

        // Cache miss - return empty for now
        // In practice, tools should be loaded during session init from Redis
        // This is just a fallback that returns empty classes
        Ok(vec![])
    }

    /// Populate cache with tools from a project config
    /// 
    /// This should be called when loading project configuration.
    /// Tool classes are derived from the `taint_class` field.
    pub async fn populate_cache(&self, tools: &[crate::core::models::ToolConfig]) -> Result<(), InterceptorError> {
        let mut cache = self.cache.write().await;
        
        for tool in tools {
            // Derive classes from taint_class field
            // If taint_class is present, use it as the single class
            // Otherwise, default to empty classes
            let classes = if let Some(ref taint_class) = tool.taint_class {
                vec![taint_class.clone()]
            } else {
                vec![]
            };
            
            cache.insert(
                tool.name.clone(),
                classes,
            );
        }
        
        Ok(())
    }
}
