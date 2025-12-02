// Redis connection pool and taint operations

use crate::core::errors::InterceptorError;
use crate::core::models::HistoryEntry;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use std::collections::HashSet;

/// Redis store for session state management
pub struct RedisStore {
    connection_manager: ConnectionManager,
}

impl RedisStore {
    /// Create a new RedisStore with connection manager
    pub async fn new(redis_url: &str) -> Result<Self, InterceptorError> {
        let client = Client::open(redis_url)
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to create Redis client: {}", e)
            ))?;

        let connection_manager = ConnectionManager::new(client)
            .await
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to create Redis connection manager: {}", e)
            ))?;

        Ok(Self { connection_manager })
    }

    /// Get all taints for a session
    pub async fn get_taints(&self, session_id: &str) -> Result<HashSet<String>, InterceptorError> {
        let mut conn = self.connection_manager.clone();
        let taint_key = format!("session:{}:taints", session_id);

        let taints: HashSet<String> = conn
            .smembers(&taint_key)
            .await
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to get taints: {}", e)
            ))?;

        Ok(taints)
    }

    /// Add a taint to a session (with TTL)
    pub async fn add_taint(&self, session_id: &str, tag: &str) -> Result<(), InterceptorError> {
        let mut conn = self.connection_manager.clone();
        let taint_key = format!("session:{}:taints", session_id);

        // Add taint to set
        conn.sadd::<_, _, ()>(&taint_key, tag)
            .await
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to add taint: {}", e)
            ))?;

        // Set TTL (1 hour)
        conn.expire::<_, ()>(&taint_key, 3600)
            .await
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to set taint TTL: {}", e)
            ))?;

        Ok(())
    }

    // Note: Redis is append-only. Taints are removed via TTL expiration only.
    // REMOVE_TAINT actions are tracked in history but not actively removed from Redis.

    /// Get session history
    pub async fn get_history(&self, session_id: &str) -> Result<Vec<HistoryEntry>, InterceptorError> {
        let mut conn = self.connection_manager.clone();
        let history_key = format!("session:{}:history", session_id);

        let raw_history: Vec<String> = conn
            .lrange(&history_key, 0, -1)
            .await
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to get history: {}", e)
            ))?;

        let history: Result<Vec<HistoryEntry>, _> = raw_history
            .iter()
            .map(|item| serde_json::from_str(item))
            .collect();

        history.map_err(|e| InterceptorError::StateError(
            format!("Failed to deserialize history: {}", e)
        ))
    }

    /// Add entry to session history (with LRU trimming and TTL)
    pub async fn add_history_entry(
        &self,
        session_id: &str,
        tool: &str,
        classes: &[String],
        timestamp: f64,
    ) -> Result<(), InterceptorError> {
        let mut conn = self.connection_manager.clone();
        let history_key = format!("session:{}:history", session_id);

        let entry = HistoryEntry {
            tool: tool.to_string(),
            classes: classes.to_vec(),
            timestamp,
        };

        let entry_json = serde_json::to_string(&entry)
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to serialize history entry: {}", e)
            ))?;

        // Append to list
        conn.rpush::<_, _, ()>(&history_key, entry_json)
            .await
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to add history entry: {}", e)
            ))?;

        // Set TTL (1 hour)
        conn.expire::<_, ()>(&history_key, 3600)
            .await
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to set history TTL: {}", e)
            ))?;

        // Trim to last 1000 entries (LRU)
        conn.ltrim::<_, ()>(&history_key, -1000, -1)
            .await
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to trim history: {}", e)
            ))?;

        Ok(())
    }

    /// Check if session has any of the forbidden taints
    pub async fn has_forbidden_taint(
        &self,
        session_id: &str,
        forbidden_tags: &[String],
    ) -> Result<bool, InterceptorError> {
        let current_taints = self.get_taints(session_id).await?;
        
        for forbidden_tag in forbidden_tags {
            if current_taints.contains(forbidden_tag) {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_redis_operations() {
        // This test requires Redis to be running
        // Skip if Redis is not available
        let redis_url = "redis://localhost:6379";
        
        if let Ok(store) = RedisStore::new(redis_url).await {
            // Use unique session ID to avoid test pollution from previous runs
            let session_id = format!("test_session_{}", Uuid::new_v4());
            
            // Test taint operations (append-only)
            store.add_taint(&session_id, "sensitive_data").await.unwrap();
            let taints = store.get_taints(&session_id).await.unwrap();
            assert!(taints.contains("sensitive_data"));
            
            // Taints expire via TTL, not explicit deletion
            
            // Test history operations
            store.add_history_entry(&session_id, "read_file", &vec!["SENSITIVE_READ".to_string()], 1234567890.0).await.unwrap();
            let history = store.get_history(&session_id).await.unwrap();
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].tool, "read_file");
        }
    }
}
