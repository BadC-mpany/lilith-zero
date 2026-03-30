// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::engine_core::crypto::CryptoSigner;
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::SyncSender;
use tracing::{error, info};

#[derive(Serialize)]
struct AuditEntry<'a> {
    session_id: &'a str,
    timestamp: f64,
    event_type: &'a str,
    details: serde_json::Value,
}

/// HMAC-signed audit logger.
///
/// Each log entry is serialised to JSON, signed with the session HMAC key, and emitted to
/// both stderr and (optionally) an append-only file via a non-blocking mpsc channel.
/// The signature enables offline tamper-detection of audit trails.
pub struct AuditLogger {
    signer: CryptoSigner,
    /// Non-blocking sender for file-write offload. `None` when file logging is disabled.
    tx: Option<SyncSender<String>>,
}

impl AuditLogger {
    /// Create a new [`AuditLogger`].
    ///
    /// If `audit_log_path` is `Some`, opens the file for appending and spawns a background
    /// thread that drains the channel and writes to it; file I/O never blocks the caller.
    ///
    /// # Errors
    /// Returns an error if `audit_log_path` is `Some` but the file cannot be opened.
    pub fn new(
        signer: CryptoSigner,
        audit_log_path: Option<PathBuf>,
    ) -> Result<Self, std::io::Error> {
        let tx = if let Some(path) = audit_log_path {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            let (tx, rx) = std::sync::mpsc::sync_channel::<String>(256);
            std::thread::spawn(move || {
                for line in rx {
                    if let Err(e) = writeln!(file, "{}", line) {
                        eprintln!("[AUDIT] File write error: {e}");
                    }
                }
            });
            Some(tx)
        } else {
            None
        };
        Ok(Self { signer, tx })
    }

    /// Emit a signed audit log entry for `session_id` with the given `event_type` and `details`.
    pub fn log(&self, session_id: &str, event_type: &str, details: serde_json::Value) {
        let timestamp = crate::utils::time::now();
        let entry = AuditEntry {
            session_id,
            timestamp,
            event_type,
            details,
        };

        let payload_str = serde_json::to_string(&entry).unwrap_or_default();
        let signature = self.signer.sign(payload_str.as_bytes());

        eprintln!("[AUDIT] {} {}", signature, payload_str);

        if let Some(tx) = &self.tx {
            let log_line = serde_json::json!({
                "signature": signature,
                "payload": payload_str,
            })
            .to_string();
            if tx.try_send(log_line).is_err() {
                error!("Audit log channel full or disconnected — entry dropped");
            }
        }

        info!(
            target: "audit",
            signature = %signature,
            payload = %payload_str,
            "SECURE_AUDIT_LOG_EMITTED"
        );
    }
}
