// Redis connection pool and taint operations

use crate::core::errors::InterceptorError;
use crate::core::models::HistoryEntry;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use std::collections::HashSet;
use tokio::time::Duration;

/// Redis store for session state management
pub struct RedisStore {
    connection_manager: ConnectionManager,
}

impl RedisStore {
    /// Create a new RedisStore with connection manager
    /// Includes retry logic, connection verification, and intelligent error handling
    /// 
    /// This method implements a robust connection strategy:
    /// 1. Pre-tests connection with simple async connection (faster failure detection)
    /// 2. Creates ConnectionManager with extended timeout for WSL port forwarding
    /// 3. Retries with exponential backoff (3 attempts)
    /// 4. Verifies connection with PING after creation
    /// 5. Provides detailed error messages for troubleshooting
    pub async fn new(redis_url: &str) -> Result<Self, InterceptorError> {
        use tokio::time::{sleep, Duration};
        
        const MAX_RETRIES: u32 = 3;
        const INITIAL_DELAY_MS: u64 = 1000; // Start with 1 second delay
        
        let mut connection_errors = Vec::new();
        
        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                let delay_ms = INITIAL_DELAY_MS * attempt as u64; // Linear backoff: 1s, 2s
                sleep(Duration::from_millis(delay_ms)).await;
            }
            
            match Self::try_create_connection(redis_url).await {
                Ok(store) => {
                    // Verify connection works by pinging
                    match store.ping().await {
                        Ok(_) => {
                            // Success! Log if this was a retry
                            if attempt > 0 {
                                tracing::info!(
                                    "Redis connection succeeded on attempt {}",
                                    attempt + 1
                                );
                            }
                            return Ok(store);
                        }
                        Err(e) => {
                            let err_msg = format!("Connection created but ping failed: {}", e);
                            connection_errors.push(err_msg);
                            continue;
                        }
                    }
                }
                Err(e) => {
                    let err_msg = format!("Attempt {} failed: {}", attempt + 1, e);
                    connection_errors.push(err_msg);
                    
                    // Log intermediate failures for debugging
                    if attempt < MAX_RETRIES - 1 {
                        tracing::warn!(
                            attempt = attempt + 1,
                            max_attempts = MAX_RETRIES,
                            error = %e,
                            "Redis connection attempt failed, retrying..."
                        );
                    }
                    continue;
                }
            }
        }
        
        // Build comprehensive error message with troubleshooting hints
        let error_details = connection_errors.join("; ");
        let troubleshooting = if redis_url.contains("localhost") || redis_url.contains("127.0.0.1") {
            format!(
                "\n\nTroubleshooting steps for WSL Redis:\n\
                1. Check Redis is running in WSL:\n\
                   - wsl redis-cli ping (should return PONG)\n\
                2. Verify port forwarding is configured:\n\
                   - netsh interface portproxy show all (should show 6379)\n\
                   - If missing, run: .\\scripts\\setup_wsl_redis_forwarding.ps1\n\
                3. Test TCP connection from Windows:\n\
                   - Test-NetConnection -ComputerName localhost -Port 6379\n\
                4. If WSL is slow to start, wait 30 seconds after 'wsl --shutdown'\n\
                5. Check Redis URL in .env: {}\n\
                6. Run diagnostics: .\\scripts\\check_redis_availability.ps1",
                redis_url
            )
        } else {
            format!("\n\nCheck Redis URL: {}", redis_url)
        };
        
        Err(InterceptorError::StateError(
            format!(
                "Failed to create Redis connection after {} attempts.\n\
                Errors: {}\n{}",
                MAX_RETRIES,
                error_details,
                troubleshooting
            )
        ))
    }
    
    /// Try to create a Redis connection (internal helper)
    /// 
    /// Strategy optimized for WSL Redis with port forwarding:
    /// 1. Create Redis client (validates URL format)
    /// 2. Skip pre-test for localhost (WSL port forwarding is slow, pre-test adds unnecessary delay)
    /// 3. Create ConnectionManager directly with extended timeout (30s for WSL)
    /// 
    /// WSL port forwarding can be very slow (10-20+ seconds) especially on first connection.
    /// The pre-test was causing unnecessary timeouts. We go straight to ConnectionManager
    /// which handles the connection establishment more efficiently.
    async fn try_create_connection(redis_url: &str) -> Result<Self, InterceptorError> {
        // Create Redis client (validates URL format)
        let client = Client::open(redis_url)
            .map_err(|e| InterceptorError::StateError(
                format!("Invalid Redis URL format '{}': {}", redis_url, e)
            ))?;

        // For WSL Redis with port forwarding, connection establishment can be very slow
        // (10-30 seconds on first connection). We use an extended timeout and skip
        // the pre-test which was causing premature timeouts.
        // 
        // ConnectionManager spawns a background task that handles connection establishment
        // more efficiently than a simple async connection.
        let connection_manager = tokio::time::timeout(
            Duration::from_secs(30), // Extended timeout for WSL port forwarding (can be 10-20s+)
            ConnectionManager::new(client)
        )
        .await
        .map_err(|_| InterceptorError::StateError(
            format!(
                "Redis ConnectionManager creation timed out after 30 seconds. \
                WSL Redis with port forwarding can be slow on first connection. \
                Verify: wsl redis-cli ping && netsh interface portproxy show all"
            )
        ))?
        .map_err(|e| InterceptorError::StateError(
            format!(
                "Failed to create Redis ConnectionManager: {}. \
                Check Redis is running: wsl redis-cli ping",
                e
            )
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

    /// Ping Redis to check connectivity
    /// Uses the actual Redis PING command for reliable health checks
    /// 
    /// WARNING: This method can panic if ConnectionManager's driver task has terminated.
    /// The health handler wraps this in panic recovery. For production use, consider
    /// using a connection pool (bb8-redis) that handles reconnection automatically.
    pub async fn ping(&self) -> Result<(), InterceptorError> {
        let mut conn = self.connection_manager.clone();
        // Use redis::cmd macro to execute PING command
        let result: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| InterceptorError::StateError(
                format!("Redis ping failed: {}", e)
            ))?;
        
        if result == "PONG" {
            Ok(())
        } else {
            Err(InterceptorError::StateError(
                format!("Redis ping returned unexpected response: {}", result)
            ))
        }
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
