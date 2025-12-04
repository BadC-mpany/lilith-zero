// Redis connection pool and taint operations

use crate::core::errors::InterceptorError;
use crate::core::models::HistoryEntry;
use crate::config::Config;
use bb8_redis::{bb8::Pool, RedisConnectionManager};
use bb8_redis::redis::AsyncCommands;
use std::collections::HashSet;
use std::ops::DerefMut;
use tokio::time::Duration as TokioDuration;

/// Redis store for session state management
/// 
/// Uses bb8-redis connection pool for automatic reconnection and connection pooling.
/// The pool automatically handles reconnection when connections break, eliminating panics.
pub struct RedisStore {
    pool: Pool<RedisConnectionManager>,
    config: Config, // Store config for timeout values
}

impl RedisStore {
    /// Create a new RedisStore with bb8-redis connection pool
    /// 
    /// Production-ready implementation with:
    /// - Lazy connection initialization (min_idle=0 during startup)
    /// - Configurable timeouts (auto-detects WSL/localhost)
    /// - Exponential backoff retry logic
    /// - Proper error diagnostics
    /// 
    /// The pool automatically handles:
    /// - Connection pooling (multiple concurrent connections)
    /// - Automatic reconnection when connections break
    /// - Graceful error handling (no panics)
    /// 
    /// # Arguments
    /// * `redis_url` - Redis connection URL (e.g., "redis://127.0.0.1:6379/0")
    /// * `config` - Application configuration containing pool settings and timeouts
    /// 
    /// # Returns
    /// * `Result<Self, InterceptorError>` - RedisStore instance or error
    pub async fn new(redis_url: &str, config: &Config) -> Result<Self, InterceptorError> {
        use tokio::time::{sleep, Duration as SleepDuration};
        
        // Production-ready connection strategy:
        // 1. Force RESP2 protocol (redis-rs 0.24+ defaults to RESP3, which hangs on WSL port forwarding)
        // 2. Create Client explicitly for URL validation
        // 3. Create pool with min_idle=0 (lazy initialization - fast, non-blocking)
        // 4. Verify pool works with a single connection (using config timeouts)
        // 5. Retry with exponential backoff on failure
        
        const MAX_RETRIES: u32 = 3;
        const INITIAL_DELAY_MS: u64 = 1000;
        
        // Use original URL - Redis 7.0.15 supports RESP3 (default for redis-rs 0.24+)
        // Previous attempts to force RESP2 failed because redis-rs doesn't respect URL parameter
        // Since Redis 7.0.15 supports RESP3, we let redis-rs use its default (RESP3)
        let effective_url = redis_url.to_string();
        
        tracing::info!(
            redis_url = redis_url,
            protocol = "RESP3 (default for redis-rs 0.24+, Redis 7.0.15 supports it)",
            "Using default RESP3 protocol (Redis 7.0.15 supports RESP3)"
        );
        
        let mut last_error = None;
        let mut connection_errors = Vec::new();
        
        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                let delay_ms = INITIAL_DELAY_MS * (1 << (attempt - 1)); // Exponential: 1s, 2s, 4s
                tracing::warn!(
                    attempt = attempt + 1,
                    max_attempts = MAX_RETRIES,
                    delay_ms = delay_ms,
                    "Retrying Redis connection..."
                );
                sleep(SleepDuration::from_millis(delay_ms)).await;
            }
            
            tracing::info!(
                attempt = attempt + 1,
                effective_url = %effective_url,
                "Attempting Redis connection (attempt {})",
                attempt + 1
            );
            
            // Test connection directly BEFORE creating pool
            // This verifies connection works with RESP3 (default for redis-rs 0.24+)
            // Redis 7.0.15 supports RESP3, so this should work
            tracing::info!("Testing direct Redis connection with RESP3 protocol (default)...");
            let test_conn_start = std::time::Instant::now();
            let test_result = tokio::time::timeout(
                TokioDuration::from_secs(config.redis_connection_timeout_secs),
                async {
                    let client = bb8_redis::redis::Client::open(effective_url.as_str())
                        .map_err(|e| format!("Failed to create Client: {}", e))?;
                    
                    let mut conn = client.get_async_connection().await
                        .map_err(|e| format!("Failed to get connection: {}", e))?;
                    
                    // Test PING with RESP3 protocol (default)
                    let result: String = bb8_redis::redis::cmd("PING")
                        .query_async(&mut conn)
                        .await
                        .map_err(|e| format!("PING failed: {}", e))?;
                    
                    if result != "PONG" {
                        return Err(format!("Unexpected PING response: {}", result));
                    }
                    
                    Ok(())
                }
            ).await;
            
            let test_duration = test_conn_start.elapsed();
            
            match test_result {
                Ok(Ok(_)) => {
                    tracing::info!(
                        duration_ms = test_duration.as_millis(),
                        effective_url = %effective_url,
                        protocol = "RESP3",
                        "Direct Redis connection test SUCCESSFUL with RESP3 protocol"
                    );
                }
                Ok(Err(e)) => {
                    let err_msg = format!("Direct connection test failed after {}ms: {}", test_duration.as_millis(), e);
                    tracing::error!(
                        error = %err_msg,
                        duration_ms = test_duration.as_millis(),
                        "Direct Redis connection test FAILED"
                    );
                    connection_errors.push(err_msg.clone());
                    last_error = Some(err_msg);
                    continue;
                }
                Err(_) => {
                    let err_msg = format!("Direct connection test timed out after {} seconds (actual: {}ms)", 
                        config.redis_connection_timeout_secs, test_duration.as_millis());
                    tracing::error!(
                        error = %err_msg,
                        timeout_secs = config.redis_connection_timeout_secs,
                        actual_duration_ms = test_duration.as_millis(),
                        "Direct Redis connection test TIMED OUT"
                    );
                    connection_errors.push(err_msg.clone());
                    last_error = Some(err_msg);
                    continue;
                }
            }
            
            // Create connection manager with URL (uses RESP3 by default, Redis 7.0.15 supports it)
            // After successful direct test, create manager for pool
            tracing::debug!("Creating RedisConnectionManager...");
            let manager_start = std::time::Instant::now();
            let manager = match RedisConnectionManager::new(effective_url.as_str()) {
                Ok(m) => {
                    tracing::debug!(
                        duration_ms = manager_start.elapsed().as_millis(),
                        protocol = "RESP3 (default)",
                        "RedisConnectionManager created successfully"
                    );
                    m
                }
                Err(e) => {
                    let err_msg = format!("Failed to create connection manager: {}", e);
                    tracing::error!(
                        error = %err_msg,
                        duration_ms = manager_start.elapsed().as_millis(),
                        "RedisConnectionManager creation failed"
                    );
                    connection_errors.push(err_msg.clone());
                    last_error = Some(err_msg);
                    continue;
                }
            };

            // Build pool with lazy initialization (min_idle=0)
            // This prevents blocking during startup with WSL port forwarding
            // Pool build timeout: connection timeout + 5s buffer (WSL can be very slow)
            // Even with min_idle=0, Pool::build() may do some initialization
            let pool_build_timeout = config.redis_connection_timeout_secs + 5;
            tracing::info!(
                pool_build_timeout = pool_build_timeout,
                connection_timeout = config.redis_connection_timeout_secs,
                max_size = config.redis_pool_max_size,
                min_idle = 0,
                "Starting Pool::build() - this may establish initial connection even with min_idle=0"
            );
            
            let pool_build_start = std::time::Instant::now();
            let pool_result = tokio::time::timeout(
                TokioDuration::from_secs(pool_build_timeout),
                async {
                    tracing::debug!("Pool::builder() starting...");
                    let builder = Pool::builder()
                        .max_size(config.redis_pool_max_size)
                        .min_idle(0) // Lazy initialization - don't block on startup
                        .max_lifetime(TokioDuration::from_secs(config.redis_pool_max_lifetime_secs))
                        .idle_timeout(Some(TokioDuration::from_secs(config.redis_pool_idle_timeout_secs)));
                    
                    tracing::debug!("Calling Pool::build(manager)...");
                    builder.build(manager).await
                }
            ).await;
            
            let pool_build_duration = pool_build_start.elapsed();
            tracing::info!(
                duration_ms = pool_build_duration.as_millis(),
                timeout_secs = pool_build_timeout,
                "Pool::build() completed (or timed out)"
            );
            
            match pool_result {
                Ok(Ok(pool)) => {
                    tracing::info!(
                        duration_ms = pool_build_duration.as_millis(),
                        "Pool::build() succeeded - pool created"
                    );
                    
                    // Verify pool works with a single connection (using config timeouts)
                    tracing::info!("Starting pool verification (get connection + PING)...");
                    let verify_start = std::time::Instant::now();
                    match Self::verify_pool_connection(&pool, config).await {
                        Ok(_) => {
                            let verify_duration = verify_start.elapsed();
                            tracing::info!(
                                protocol = "RESP3 (default, Redis 7.0.15 supports it)",
                                max_size = config.redis_pool_max_size,
                                connection_timeout = config.redis_connection_timeout_secs,
                                operation_timeout = config.redis_operation_timeout_secs,
                                url = %effective_url,
                                pool_build_ms = pool_build_duration.as_millis(),
                                verify_ms = verify_duration.as_millis(),
                                total_ms = (pool_build_duration + verify_duration).as_millis(),
                                "Redis connection pool initialized successfully"
                            );
                            
                            if attempt > 0 {
                                tracing::info!(
                                    "Redis connection succeeded on attempt {}",
                                    attempt + 1
                                );
                            }
                            
                            return Ok(Self { pool, config: config.clone() });
                        }
                        Err(e) => {
                            let verify_duration = verify_start.elapsed();
                            let err_msg = format!("Pool created but verification failed after {}ms: {}", verify_duration.as_millis(), e);
                            tracing::error!(
                                error = %err_msg,
                                pool_build_ms = pool_build_duration.as_millis(),
                                verify_ms = verify_duration.as_millis(),
                                "Pool verification failed"
                            );
                            connection_errors.push(err_msg.clone());
                            last_error = Some(err_msg);
                            continue;
                        }
                    }
                }
                Ok(Err(e)) => {
                    let err_msg = format!("Pool::build() returned error after {}ms: {}", pool_build_duration.as_millis(), e);
                    tracing::error!(
                        error = %err_msg,
                        duration_ms = pool_build_duration.as_millis(),
                        "Pool::build() failed with error"
                    );
                    connection_errors.push(err_msg.clone());
                    last_error = Some(err_msg);
                    continue;
                }
                Err(_) => {
                    let err_msg = format!(
                        "Pool::build() timed out after {} seconds (connection_timeout={}s + 5s buffer). \
                        Actual duration: {}ms. For WSL, try REDIS_CONNECTION_TIMEOUT_SECS=20",
                        pool_build_timeout,
                        config.redis_connection_timeout_secs,
                        pool_build_duration.as_millis()
                    );
                    tracing::error!(
                        error = %err_msg,
                        timeout_secs = pool_build_timeout,
                        actual_duration_ms = pool_build_duration.as_millis(),
                        "Pool::build() timed out"
                    );
                    connection_errors.push(err_msg.clone());
                    last_error = Some(err_msg);
                    continue;
                }
            }
        }
        
        // All retries failed - provide comprehensive diagnostics
        let error_summary = connection_errors.join("; ");
        let troubleshooting = if redis_url.contains("localhost") || redis_url.contains("127.0.0.1") {
            format!(
                "\n\nTroubleshooting steps for WSL Redis:\n\
                1. Verify Redis is running:\n\
                   - wsl redis-cli ping (should return PONG)\n\
                2. Check port forwarding:\n\
                   - netsh interface portproxy show all (should show 6379)\n\
                   - If missing, run: .\\scripts\\fix_wsl_redis_connection.ps1\n\
                3. Test actual Redis connectivity (not just TCP):\n\
                   - .\\scripts\\diagnose_redis_connection.ps1\n\
                4. Check WSL IP hasn't changed:\n\
                   - wsl hostname -I\n\
                   - Update port forwarding if IP changed: .\\scripts\\fix_wsl_redis_connection.ps1\n\
                5. Verify Redis binding:\n\
                   - Redis must be bound to 0.0.0.0 (not 127.0.0.1)\n\
                   - Fix: .\\scripts\\fix_wsl_redis_connection.ps1\n\
                6. Protocol: Using RESP3 (default for redis-rs 0.24+, Redis 7.0.15 supports it)\n\
                7. Effective Redis URL: {}\n\
                8. Original URL: {}",
                effective_url,
                redis_url
            )
        } else {
            format!(
                "\n\nCheck Redis URL: {}\n\
                Effective URL (with RESP2): {}",
                redis_url,
                effective_url
            )
        };
        
        Err(InterceptorError::StateError(
            format!(
                "Failed to create Redis connection pool after {} attempts.\n\
                Errors encountered:\n{}\n\
                Last error: {}{}",
                MAX_RETRIES,
                error_summary,
                last_error.unwrap_or_else(|| "Unknown error".to_string()),
                troubleshooting
            )
        ))
    }
    
    /// Verify pool connection by getting a connection and pinging
    /// 
    /// Production-ready with configurable timeout protection and detailed logging.
    async fn verify_pool_connection(
        pool: &Pool<RedisConnectionManager>,
        config: &Config
    ) -> Result<(), InterceptorError> {
        tracing::debug!(
            connection_timeout = config.redis_connection_timeout_secs,
            "Attempting to get connection from pool..."
        );
        
        // Get connection with configurable timeout
        let conn_get_start = std::time::Instant::now();
        let conn_result = tokio::time::timeout(
            TokioDuration::from_secs(config.redis_connection_timeout_secs),
            pool.get()
        ).await;
        
        let conn_get_duration = conn_get_start.elapsed();
        
        let mut conn = match conn_result {
            Ok(Ok(c)) => {
                tracing::debug!(
                    duration_ms = conn_get_duration.as_millis(),
                    "Connection acquired from pool successfully"
                );
                c
            }
            Ok(Err(e)) => {
                let err_msg = format!("Failed to get connection after {}ms: {}", conn_get_duration.as_millis(), e);
                tracing::error!(
                    error = %err_msg,
                    duration_ms = conn_get_duration.as_millis(),
                    "Connection acquisition failed"
                );
                return Err(InterceptorError::StateError(err_msg));
            }
            Err(_) => {
                let err_msg = format!("Connection acquisition timed out after {} seconds (actual: {}ms)", 
                    config.redis_connection_timeout_secs, conn_get_duration.as_millis());
                tracing::error!(
                    error = %err_msg,
                    timeout_secs = config.redis_connection_timeout_secs,
                    actual_duration_ms = conn_get_duration.as_millis(),
                    "Connection acquisition timed out"
                );
                return Err(InterceptorError::StateError(err_msg));
            }
        };
        
        // Ping with configurable timeout
        tracing::debug!(
            operation_timeout = config.redis_operation_timeout_secs,
            "Executing PING command..."
        );
        let ping_start = std::time::Instant::now();
        let ping_result = tokio::time::timeout(
            TokioDuration::from_secs(config.redis_operation_timeout_secs),
            bb8_redis::redis::cmd("PING")
                .query_async(conn.deref_mut())
        ).await;
        
        let ping_duration = ping_start.elapsed();
        
        let result: String = match ping_result {
            Ok(Ok(r)) => {
                tracing::debug!(
                    duration_ms = ping_duration.as_millis(),
                    response = %r,
                    "PING command completed"
                );
                r
            }
            Ok(Err(e)) => {
                let err_msg = format!("PING failed after {}ms: {}", ping_duration.as_millis(), e);
                tracing::error!(
                    error = %err_msg,
                    duration_ms = ping_duration.as_millis(),
                    "PING command failed"
                );
                return Err(InterceptorError::StateError(err_msg));
            }
            Err(_) => {
                let err_msg = format!("PING timed out after {} seconds (actual: {}ms)", 
                    config.redis_operation_timeout_secs, ping_duration.as_millis());
                tracing::error!(
                    error = %err_msg,
                    timeout_secs = config.redis_operation_timeout_secs,
                    actual_duration_ms = ping_duration.as_millis(),
                    "PING command timed out"
                );
                return Err(InterceptorError::StateError(err_msg));
            }
        };
        
        if result != "PONG" {
            let err_msg = format!("Unexpected PING response: {} (expected PONG)", result);
            tracing::error!(
                error = %err_msg,
                response = %result,
                "PING returned unexpected response"
            );
            return Err(InterceptorError::StateError(err_msg));
        }
        
        tracing::debug!(
            total_duration_ms = (conn_get_duration + ping_duration).as_millis(),
            conn_ms = conn_get_duration.as_millis(),
            ping_ms = ping_duration.as_millis(),
            "Pool verification successful"
        );
        
        Ok(())
    }

    /// Get all taints for a session
    /// 
    /// Production-ready implementation with configurable timeout protection.
    pub async fn get_taints(&self, session_id: &str) -> Result<HashSet<String>, InterceptorError> {
        // Get connection with configurable timeout
        let mut conn = tokio::time::timeout(
            TokioDuration::from_secs(self.config.redis_connection_timeout_secs),
            self.pool.get()
        ).await
        .map_err(|_| InterceptorError::StateError(
            format!("Connection timeout after {} seconds", self.config.redis_connection_timeout_secs)
        ))?
        .map_err(|e| InterceptorError::StateError(
            format!("Failed to get connection: {}", e)
        ))?;
        
        let taint_key = format!("session:{}:taints", session_id);

        // Execute Redis command with configurable timeout
        let taints: HashSet<String> = tokio::time::timeout(
            TokioDuration::from_secs(self.config.redis_operation_timeout_secs),
            conn.smembers(&taint_key)
        ).await
        .map_err(|_| InterceptorError::StateError(
            format!("SMEMBERS timed out after {} seconds for key: {}", self.config.redis_operation_timeout_secs, taint_key)
        ))?
        .map_err(|e| InterceptorError::StateError(
            format!("Failed to get taints: {}", e)
        ))?;
        
        Ok(taints)
    }

    /// Add a taint to a session (with TTL)
    pub async fn add_taint(&self, session_id: &str, tag: &str) -> Result<(), InterceptorError> {
        let mut conn = self.pool.get().await
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to get connection from pool: {}", e)
            ))?;
        
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
        let mut conn = self.pool.get().await
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to get connection from pool: {}", e)
            ))?;
        
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
        let mut conn = self.pool.get().await
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to get connection from pool: {}", e)
            ))?;
        
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
    /// The connection pool automatically handles reconnection, so this method
    /// will never panic. Errors are returned as Result types.
    pub async fn ping(&self) -> Result<(), InterceptorError> {
        let mut conn = self.pool.get().await
            .map_err(|e| InterceptorError::StateError(
                format!("Failed to get connection from pool: {}", e)
            ))?;
        
        // Use bb8-redis's redis::cmd macro to execute PING command
        // The connection from bb8-redis pool implements AsyncCommands trait
        let result: String = bb8_redis::redis::cmd("PING")
            .query_async(conn.deref_mut())
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
        use crate::config::Config;
        
        let redis_url = "redis://localhost:6379";
        let config = Config::test_config();
        
        if let Ok(store) = RedisStore::new(redis_url, &config).await {
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
