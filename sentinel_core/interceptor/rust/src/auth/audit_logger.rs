// Security event logging

use crate::auth::api_key::ApiKeyHash;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};

/// Authentication event type
#[derive(Debug, Clone)]
pub enum AuthEvent {
    AuthSuccess,
    AuthFailure { reason: String },
}

/// Audit logger for security events
pub struct AuditLogger {
    db_pool: Option<Arc<PgPool>>,
}

impl AuditLogger {
    /// Create a new audit logger
    /// 
    /// If `db_pool` is `None`, only structured logging will be used (no database persistence).
    pub fn new(db_pool: Option<Arc<PgPool>>) -> Self {
        Self { db_pool }
    }

    /// Log an authentication event
    /// 
    /// This is fire-and-forget: it spawns an async task and doesn't block the request.
    /// Errors are logged but don't affect the request flow.
    pub fn log_auth_event(
        &self,
        event: AuthEvent,
        api_key_hash: Option<&ApiKeyHash>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) {
        let db_pool = self.db_pool.clone();
        let hash_str = api_key_hash.map(|h| h.as_str().to_string());
        let ip = ip_address.map(|s| s.to_string());
        let ua = user_agent.map(|s| s.to_string());
        let event_clone = event.clone();

        // Fire-and-forget async task
        tokio::spawn(async move {
            // Structured logging
            match event_clone {
                AuthEvent::AuthSuccess => {
                    info!(
                        api_key_hash = ?hash_str,
                        ip_address = ?ip,
                        user_agent = ?ua,
                        "Authentication successful"
                    );
                }
                AuthEvent::AuthFailure { ref reason } => {
                    warn!(
                        api_key_hash = ?hash_str,
                        ip_address = ?ip,
                        user_agent = ?ua,
                        reason = %reason,
                        "Authentication failed"
                    );
                }
            }

            // Database logging (if pool available)
            if let Some(pool) = db_pool {
                let event_type = match event_clone {
                    AuthEvent::AuthSuccess => "AUTH_SUCCESS",
                    AuthEvent::AuthFailure { .. } => "AUTH_FAILURE",
                };

                // Fire-and-forget database insert (errors are logged but don't block)
                // PostgreSQL INET type: pass None for NULL, or the IP string (PostgreSQL will parse it)
                // Using Option<&str> allows sqlx to handle NULL properly
                let ip_opt: Option<&str> = ip.as_deref();
                
                if let Err(e) = sqlx::query(
                    "INSERT INTO auth_audit_log (api_key_hash, event_type, ip_address, user_agent, created_at)
                     VALUES ($1, $2, $3::inet, $4, NOW())"
                )
                .bind(&hash_str)
                .bind(event_type)
                .bind(ip_opt)
                .bind(&ua)
                .execute(pool.as_ref())
                .await
                {
                    // Log database error but don't fail the request
                    warn!(
                        error = %e,
                        "Failed to write audit log to database"
                    );
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_logger_creation() {
        let _logger = AuditLogger::new(None);
        // Just verify it can be created
        assert!(true);
    }

    #[tokio::test]
    async fn test_audit_logger_logging() {
        let logger = AuditLogger::new(None);
        let hash = ApiKeyHash::from_api_key("test_key");

        // Should not panic
        logger.log_auth_event(
            AuthEvent::AuthSuccess,
            Some(&hash),
            Some("127.0.0.1"),
            Some("test-agent"),
        );

        // Give async task a moment to complete
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}
