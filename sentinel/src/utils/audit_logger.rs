//! Structured Audit Logger
//!
//! This module provides a structured logging facility that emits JSON logs to stderr.
//! These logs are distinct from debug/info logs and are intended for security auditing.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    SessionStart,
    ToolCall,
    Decision,
    TaintViolation,
    SystemError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: f64,
    pub session_id: String,
    pub event_type: AuditEventType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

pub struct AuditLogger;

impl AuditLogger {
    pub fn log(entry: AuditEntry) {
        if let Ok(json) = serde_json::to_string(&entry) {
            eprintln!("{}", json);
        }
    }

    pub fn now() -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    }
}
