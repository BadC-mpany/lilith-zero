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
        
        const MAX_RETRIES: u32 = 3;
        const INITIAL_DELAY_MS: u64 = 1000;
        
        // === CRITICAL FIX: BYPASS PORT PROXY BY CONNECTING DIRECTLY TO WSL IP ===
        // The Windows-to-WSL port proxy (netsh v4tov4) drops RESP3 'HELLO' handshake packets.
        // Even RESP2 fails over the proxy because redis-rs Client doesn't respect ?protocol=resp2.
        // 
        // SOLUTION: Connect directly to WSL IP address, bypassing the port proxy entirely.
        // This allows both RESP2 and RESP3 to work, as there's no proxy interference.
        
        // Detect if we're connecting to localhost/127.0.0.1 (indicates WSL port forwarding)
        let mut effective_url = redis_url.to_string();
        if effective_url.contains("127.0.0.1") || effective_url.contains("localhost") {
            // Get WSL IP address dynamically
            tracing::info!("Detected localhost connection - attempting to resolve WSL IP...");
            let wsl_ip = Self::get_wsl_ip().await;
            
            match wsl_ip {
                Ok(ip) => {
                    // Replace localhost/127.0.0.1 with WSL IP
                    effective_url = effective_url
                        .replace("127.0.0.1", &ip)
                        .replace("localhost", &ip);
                    
                    tracing::info!(
                        original_url = redis_url,
                        effective_url = %effective_url,
                        wsl_ip = %ip,
                        "Bypassing port proxy: connecting directly to WSL IP"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Failed to get WSL IP, falling back to original URL with RESP2 parameter"
                    );
                    // Fallback: try RESP2 parameter (may not work, but worth trying)
                    if !effective_url.contains("protocol=") {
                        if effective_url.contains('?') {
                            effective_url.push_str("&protocol=resp2");
                        } else {
                            effective_url.push_str("?protocol=resp2");
                        }
                    }
                }
            }
        } else {
            // Not localhost - use URL as-is, but add RESP2 parameter for safety
            if !effective_url.contains("protocol=") {
                if effective_url.contains('?') {
                    effective_url.push_str("&protocol=resp2");
                } else {
                    effective_url.push_str("?protocol=resp2");
                }
            }
        }
        
        tracing::info!(
            original_url = redis_url,
            effective_url = %effective_url,
            protocol = "RESP2 (Forced via URL parameter - required for WSL port forwarding)",
            "Initializing Redis connection with RESP2 protocol"
        );
        
        let mut connection_errors = Vec::new();
        
        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                let delay_ms = INITIAL_DELAY_MS * (1 << (attempt - 1));
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
                protocol = "RESP2",
                "Attempting Redis connection (attempt {})",
                attempt + 1
            );
            
            // Pre-flight test: Verify direct connection works (using effective_url which may be WSL IP)
            // This helps diagnose if the issue is connectivity-related or pool-related
            tracing::debug!("Pre-flight: Testing direct connection to effective URL...");
            let preflight_start = std::time::Instant::now();
            let preflight_result = tokio::time::timeout(
                TokioDuration::from_secs(5),
                async {
                    use bb8_redis::redis::Client;
                    let client = Client::open(effective_url.as_str())?;
                    let mut conn = client.get_async_connection().await?;
                    bb8_redis::redis::cmd("PING").query_async::<_, String>(&mut conn).await
                }
            ).await;
            
            match preflight_result {
                Ok(Ok(result)) if result == "PONG" => {
                    tracing::info!(
                        duration_ms = preflight_start.elapsed().as_millis(),
                        effective_url = %effective_url,
                        "Pre-flight connection test: SUCCESS"
                    );
                }
                Ok(Ok(result)) => {
                    let err_msg = format!("Pre-flight test returned unexpected result: {} (expected PONG)", result);
                    tracing::error!(error = %err_msg, "Pre-flight test failed");
                    connection_errors.push(err_msg);
                    continue;
                }
                Ok(Err(e)) => {
                    let err_msg = format!("Pre-flight connection test failed: {}", e);
                    tracing::error!(error = %err_msg, effective_url = %effective_url, "Pre-flight test failed");
                    connection_errors.push(err_msg);
                    continue;
                }
                Err(_) => {
                    let err_msg = format!("Pre-flight connection test timed out after 5s (URL: {})", effective_url);
                    tracing::error!(error = %err_msg, "Pre-flight test timed out");
                    connection_errors.push(err_msg);
                    continue;
                }
            }
            
            // Create Manager with RESP2 URL (pre-flight test passed, so this should work)
            let manager = match RedisConnectionManager::new(effective_url.as_str()) {
                Ok(m) => {
                    tracing::debug!("RedisConnectionManager created successfully");
                    m
                },
                Err(e) => {
                    let err_msg = format!("Failed to create connection manager: {}", e);
                    connection_errors.push(err_msg);
                    continue;
                }
            };
            
            // 4. Build Pool (Lazy)
            let pool_build_timeout = config.redis_connection_timeout_secs + 5;
            tracing::info!("Building pool with RESP2 (Attempt {})...", attempt + 1);
            
            let pool_result = tokio::time::timeout(
                TokioDuration::from_secs(pool_build_timeout),
                Pool::builder()
                    .max_size(config.redis_pool_max_size)
                    .min_idle(0) 
                    .max_lifetime(Some(TokioDuration::from_secs(config.redis_pool_max_lifetime_secs)))
                    .idle_timeout(Some(TokioDuration::from_secs(config.redis_pool_idle_timeout_secs)))
                    .build(manager)
            ).await;
            
            match pool_result {
                Ok(Ok(pool)) => {
                    // 5. Verify Connection
                    // Pre-flight test passed, so pool verification should work too
                    tracing::info!("Verifying pool connection (PING)...");
                    match Self::verify_pool_connection(&pool, config).await {
                        Ok(_) => {
                            tracing::info!(
                                effective_url = %effective_url,
                                "Redis connection pool verified successfully"
                            );
                            return Ok(Self { pool, config: config.clone() });
                        }
                        Err(e) => {
                            let err_msg = format!("Handshake failed: {}", e);
                            tracing::error!(error = %err_msg, "Verification failed");
                            connection_errors.push(err_msg);
                            continue;
                        }
                    }
                }
                Ok(Err(e)) => {
                    let err_msg = format!("Pool build error: {}", e);
                    connection_errors.push(err_msg);
                    continue;
                }
                Err(_) => {
                    let err_msg = format!("Pool build timed out after {}s", pool_build_timeout);
                    connection_errors.push(err_msg);
                    continue;
                }
            }
        }
        
        Err(InterceptorError::StateError(format!(
            "Failed to connect to Redis after {} attempts.\nErrors: {}\nOriginal URL: {}\nEffective URL: {}", 
            MAX_RETRIES, 
            connection_errors.join("; "), 
            redis_url,
            effective_url
        )))
    }
    
    /// Get WSL IP address by executing `wsl hostname -I`
    /// 
    /// Returns the first IP address from WSL's hostname command.
    /// This IP can be used to connect directly to WSL services, bypassing port forwarding.
    async fn get_wsl_ip() -> Result<String, String> {
        use tokio::process::Command;
        
        let output = Command::new("wsl")
            .arg("hostname")
            .arg("-I")
            .output()
            .await
            .map_err(|e| format!("Failed to execute wsl hostname -I: {}", e))?;
        
        if !output.status.success() {
            return Err(format!("wsl hostname -I failed with status: {:?}", output.status.code()));
        }
        
        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| format!("Invalid UTF-8 from wsl hostname -I: {}", e))?;
        
        // Extract first IP address (WSL may return multiple IPs)
        let ip = stdout.trim().split_whitespace().next()
            .ok_or_else(|| "No IP address found in wsl hostname -I output".to_string())?
            .to_string();
        
        // Validate IP format (basic check)
        if !ip.contains('.') {
            return Err(format!("Invalid IP format from wsl hostname -I: {}", ip));
        }
        
        Ok(ip)
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
    /// Production-ready implementation with ULTRA-FAST FAIL strategy:
    /// - Connection acquisition: 2 seconds max (fast fail - don't wait for broken pool)
    /// - Operation execution: 1 second max (fast fail - don't wait for broken connection)
    /// - Total max time: 3 seconds (but typically <500ms if Redis is healthy)
    /// - Returns error on timeout/failure (handler converts to empty set - fail-safe)
    pub async fn get_taints(&self, session_id: &str) -> Result<HashSet<String>, InterceptorError> {
        use tracing::{info, warn};
        
        let taint_key = format!("session:{}:taints", session_id);
        info!(session_id = session_id, taint_key = %taint_key, "Getting session taints from Redis");
        
        let operation_start = std::time::Instant::now();
        
        // Step 1: Get connection from pool (ULTRA-FAST FAIL: 2 seconds max)
        // CRITICAL: If pool.get() hangs, fail fast - don't wait for broken connections
        // This ensures Redis never blocks request processing
        const CONNECTION_TIMEOUT_SECS: u64 = 2; // Fast fail - don't wait for broken pool
        let mut conn = match tokio::time::timeout(
            TokioDuration::from_secs(CONNECTION_TIMEOUT_SECS),
            self.pool.get()
        ).await {
            Ok(Ok(c)) => {
                info!(
                    duration_ms = operation_start.elapsed().as_millis(),
                    "Connection acquired from pool"
                );
                c
            },
            Ok(Err(e)) => {
                warn!(
                    duration_ms = operation_start.elapsed().as_millis(),
                    error = %e,
                    "Failed to get connection from pool"
                );
                return Err(InterceptorError::StateError(
                    format!("Pool error: {}", e)
                ));
            },
            Err(_) => {
                warn!(
                    duration_ms = operation_start.elapsed().as_millis(),
                    timeout_secs = CONNECTION_TIMEOUT_SECS,
                    "Connection acquisition timed out - Redis unavailable"
                );
                return Err(InterceptorError::StateError(
                    format!("Connection timeout after {} seconds - Redis unavailable", CONNECTION_TIMEOUT_SECS)
                ));
            }
        };

        // Step 2: Execute SMEMBERS with fast operation timeout (1 second)
        // Once connection is established, operations should be fast
        // If operation times out, connection is likely broken
        const OPERATION_TIMEOUT_SECS: u64 = 1; // Fast fail: 1 second for operation
        let smembers_start = std::time::Instant::now();
        info!(taint_key = %taint_key, "Executing SMEMBERS command...");
        match tokio::time::timeout(
            TokioDuration::from_secs(OPERATION_TIMEOUT_SECS),
            bb8_redis::redis::cmd("SMEMBERS")
                .arg(&taint_key)
                .query_async::<_, HashSet<String>>(conn.deref_mut())
        ).await {
            Ok(Ok(taints)) => {
                let smembers_duration = smembers_start.elapsed();
                let total_duration = operation_start.elapsed();
                info!(
                    duration_ms = smembers_duration.as_millis(),
                    total_ms = total_duration.as_millis(),
                    taint_count = taints.len(),
                    "SMEMBERS completed successfully"
                );
                Ok(taints)
            },
            Ok(Err(e)) => {
                warn!(
                    duration_ms = smembers_start.elapsed().as_millis(),
                    error = %e,
                    "SMEMBERS command failed"
                );
                Err(InterceptorError::StateError(
                    format!("SMEMBERS failed: {}", e)
                ))
            },
            Err(_) => {
                warn!(
                    duration_ms = smembers_start.elapsed().as_millis(),
                    timeout_secs = OPERATION_TIMEOUT_SECS,
                    "SMEMBERS command timed out - connection may be broken"
                );
                Err(InterceptorError::StateError(
                    format!("SMEMBERS timeout after {} seconds", OPERATION_TIMEOUT_SECS)
                ))
            }
        }
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
    /// 
    /// Production-ready implementation with ULTRA-FAST FAIL strategy:
    /// - Connection acquisition: 2 seconds max (fast fail - don't wait for broken pool)
    /// - Operation execution: 1 second max (fast fail - don't wait for broken connection)
    /// - Returns error on timeout/failure (caller should handle gracefully - fail-safe)
    pub async fn get_history(&self, session_id: &str) -> Result<Vec<HistoryEntry>, InterceptorError> {
        use tracing::{info, warn};
        
        let history_key = format!("session:{}:history", session_id);
        info!(session_id = session_id, history_key = %history_key, "Getting session history from Redis");
        
        let operation_start = std::time::Instant::now();
        
        // Step 1: Get connection from pool (ULTRA-FAST FAIL: 2 seconds max)
        // CRITICAL: If pool.get() hangs, fail fast - don't wait for broken connections
        const CONNECTION_TIMEOUT_SECS: u64 = 2; // Fast fail - don't wait for broken pool
        let mut conn = match tokio::time::timeout(
            TokioDuration::from_secs(CONNECTION_TIMEOUT_SECS),
            self.pool.get()
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
                    timeout_secs = CONNECTION_TIMEOUT_SECS,
                    "Connection acquisition timed out for history - Redis unavailable"
                );
                return Err(InterceptorError::StateError(
                    format!("Connection timeout after {} seconds - Redis unavailable", CONNECTION_TIMEOUT_SECS)
                ));
            }
        };

        // Step 2: Execute LRANGE with fast operation timeout (1 second)
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
    /// 
    /// IMPORTANT: Uses configurable timeout to prevent hanging on broken connections.
    pub async fn ping(&self) -> Result<(), InterceptorError> {
        use tracing::{debug, warn};
        
        debug!("Acquiring connection from pool for PING...");
        let conn_start = std::time::Instant::now();
        let mut conn = match tokio::time::timeout(
            TokioDuration::from_secs(self.config.redis_connection_timeout_secs),
            self.pool.get()
        ).await {
            Ok(Ok(c)) => {
                debug!(
                    duration_ms = conn_start.elapsed().as_millis(),
                    "Connection acquired for PING"
                );
                c
            },
            Ok(Err(e)) => {
                warn!(
                    duration_ms = conn_start.elapsed().as_millis(),
                    error = %e,
                    "Failed to get connection from pool for PING"
                );
                return Err(InterceptorError::StateError(
                    format!("Failed to get connection: {}", e)
                ));
            },
            Err(_) => {
                warn!(
                    duration_ms = conn_start.elapsed().as_millis(),
                    timeout_secs = self.config.redis_connection_timeout_secs,
                    "Connection acquisition timed out for PING"
                );
                return Err(InterceptorError::StateError(
                    format!("Connection timeout after {} seconds", self.config.redis_connection_timeout_secs)
                ));
            }
        };
        
        debug!("Executing PING command...");
        let ping_start = std::time::Instant::now();
        // Use bb8-redis's redis::cmd macro to execute PING command with timeout
        let result: String = match tokio::time::timeout(
            TokioDuration::from_secs(self.config.redis_operation_timeout_secs),
            bb8_redis::redis::cmd("PING").query_async(conn.deref_mut())
        ).await {
            Ok(Ok(r)) => {
                debug!(
                    duration_ms = ping_start.elapsed().as_millis(),
                    "PING completed successfully"
                );
                r
            },
            Ok(Err(e)) => {
                warn!(
                    duration_ms = ping_start.elapsed().as_millis(),
                    error = %e,
                    "PING command failed"
                );
                return Err(InterceptorError::StateError(
                    format!("Redis ping failed: {}", e)
                ));
            },
            Err(_) => {
                warn!(
                    duration_ms = ping_start.elapsed().as_millis(),
                    timeout_secs = self.config.redis_operation_timeout_secs,
                    "PING command timed out - connection may be broken"
                );
                return Err(InterceptorError::StateError(
                    format!("Redis ping timed out after {} seconds", self.config.redis_operation_timeout_secs)
                ));
            }
        };
        
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
