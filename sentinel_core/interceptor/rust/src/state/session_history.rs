// Session history tracking - modular implementation for session history operations

use crate::core::errors::InterceptorError;
use crate::core::models::HistoryEntry;
use bb8_redis::{bb8::Pool, RedisConnectionManager};
use bb8_redis::redis::AsyncCommands;
use std::ops::DerefMut;
use tokio::time::Duration as TokioDuration;

/// Session history operations
/// 
/// Provides methods for reading and writing session history to Redis.
/// Session history tracks tool executions for pattern matching in policy evaluation.
pub struct SessionHistory;

impl SessionHistory {
    /// Get session history from Redis
    /// 
    /// Production-ready implementation with ULTRA-FAST FAIL strategy:
    /// - Connection acquisition: 2 seconds max (fast fail - don't wait for broken pool)
    /// - Operation execution: 1 second max (fast fail - don't wait for broken connection)
    /// - Returns error on timeout/failure (caller should handle gracefully - fail-safe)
    pub async fn get_history(
        pool: &Pool<RedisConnectionManager>,
        session_id: &str,
    ) -> Result<Vec<HistoryEntry>, InterceptorError> {
        use tracing::{info, warn};
        
        let history_key = format!("session:{}:history", session_id);
        info!(session_id = session_id, history_key = %history_key, "Getting session history from Redis");
        
        let operation_start = std::time::Instant::now();
        
        // Step 1: Get connection from pool (fast-fail timeout for read operations)
        // CRITICAL: Read operations must complete quickly (<2s) to match handler timeout
        // Use shorter timeout (2s) for read operations instead of full connection timeout (15s)
        const READ_OPERATION_CONNECTION_TIMEOUT_SECS: u64 = 2; // Fast-fail for read operations
        let mut conn = match tokio::time::timeout(
            TokioDuration::from_secs(READ_OPERATION_CONNECTION_TIMEOUT_SECS),
            pool.get()
        ).await {
            Ok(Ok(c)) => {
                info!(
                    duration_ms = operation_start.elapsed().as_millis(),
                    "Connection acquired from pool for history"
                );
                c
            },
            Ok(Err(e)) => {
                warn!(
                    duration_ms = operation_start.elapsed().as_millis(),
                    error = %e,
                    "Failed to get connection from pool for history"
                );
                return Err(InterceptorError::StateError(
                    format!("Pool error: {}", e)
                ));
            },
            Err(_) => {
                warn!(
                    duration_ms = operation_start.elapsed().as_millis(),
                    timeout_secs = READ_OPERATION_CONNECTION_TIMEOUT_SECS,
                    "Connection acquisition timed out for history - Redis unavailable"
                );
                return Err(InterceptorError::StateError(
                    format!("Connection timeout after {} seconds - Redis unavailable", READ_OPERATION_CONNECTION_TIMEOUT_SECS)
                ));
            }
        };

        // Step 2: Execute LRANGE with fast operation timeout (1 second)
        // Note: No ping check for read operations - connection was just acquired, ping adds unnecessary overhead
        const OPERATION_TIMEOUT_SECS: u64 = 1; // Fast fail: 1 second for operation
        let lrange_start = std::time::Instant::now();
        info!(history_key = %history_key, "Executing LRANGE command...");
        let raw_history: Vec<String> = match tokio::time::timeout(
            TokioDuration::from_secs(OPERATION_TIMEOUT_SECS),
            bb8_redis::redis::cmd("LRANGE")
                .arg(&history_key)
                .arg(0)
                .arg(-1)
                .query_async::<_, Vec<String>>(conn.deref_mut())
        ).await {
            Ok(Ok(history)) => {
                let lrange_duration = lrange_start.elapsed();
                let total_duration = operation_start.elapsed();
                info!(
                    duration_ms = lrange_duration.as_millis(),
                    total_ms = total_duration.as_millis(),
                    entry_count = history.len(),
                    "LRANGE completed successfully"
                );
                history
            },
            Ok(Err(e)) => {
                warn!(
                    duration_ms = lrange_start.elapsed().as_millis(),
                    error = %e,
                    "LRANGE command failed"
                );
                return Err(InterceptorError::StateError(
                    format!("LRANGE failed: {}", e)
                ));
            },
            Err(_) => {
                warn!(
                    duration_ms = lrange_start.elapsed().as_millis(),
                    timeout_secs = OPERATION_TIMEOUT_SECS,
                    "LRANGE command timed out - connection may be broken"
                );
                return Err(InterceptorError::StateError(
                    format!("LRANGE timeout after {} seconds", OPERATION_TIMEOUT_SECS)
                ));
            }
        };

        // Step 3: Deserialize history entries
        let history: Result<Vec<HistoryEntry>, _> = raw_history
            .iter()
            .map(|item| serde_json::from_str(item))
            .collect();

        history.map_err(|e| InterceptorError::StateError(
            format!("Failed to deserialize history: {}", e)
        ))
    }

    /// Add entry to session history (with LRU trimming and TTL)
    /// 
    /// # Arguments
    /// * `pool` - Redis connection pool
    /// * `session_id` - Session identifier
    /// * `tool` - Tool name
    /// * `classes` - Tool security classes
    /// * `timestamp` - Unix timestamp of the execution
    /// * `connection_timeout_secs` - Connection acquisition timeout
    pub async fn add_history_entry(
        pool: &Pool<RedisConnectionManager>,
        session_id: &str,
        tool: &str,
        classes: &[String],
        timestamp: f64,
        connection_timeout_secs: u64,
    ) -> Result<(), InterceptorError> {
        let mut conn = match tokio::time::timeout(
            TokioDuration::from_secs(connection_timeout_secs),
            pool.get()
        ).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(InterceptorError::StateError(
                format!("Failed to get connection from pool: {}", e)
            )),
            Err(_) => return Err(InterceptorError::StateError(
                format!("Connection timeout after {} seconds", connection_timeout_secs)
            )),
        };

        // Health check: ping connection before use
        Self::ping_connection(&mut conn).await?;
        
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

    /// Ping connection to ensure it's alive before use
    async fn ping_connection(
        conn: &mut bb8_redis::bb8::PooledConnection<'_, RedisConnectionManager>
    ) -> Result<(), InterceptorError> {
        use tracing::debug;
        debug!("Pinging connection to verify health...");
        match tokio::time::timeout(
            TokioDuration::from_secs(1), // Fast ping timeout
            bb8_redis::redis::cmd("PING").query_async::<_, String>(conn.deref_mut())
        ).await {
            Ok(Ok(result)) if result == "PONG" => Ok(()),
            Ok(Ok(_)) => Err(InterceptorError::StateError("Unexpected PING response".to_string())),
            Ok(Err(e)) => Err(InterceptorError::StateError(format!("PING failed: {}", e))),
            Err(_) => Err(InterceptorError::StateError("PING timeout".to_string())),
        }
    }
}
