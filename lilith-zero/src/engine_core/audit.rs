// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::engine_core::crypto::CryptoSigner;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing::{error, info};

#[derive(Serialize)]
struct AuditEntry<'a> {
    session_id: &'a str,
    timestamp: f64,
    event_type: &'a str,
    details: serde_json::Value,
}

pub struct AuditLogger {
    signer: CryptoSigner,
    file_writer: Option<Arc<Mutex<File>>>,
}

impl AuditLogger {
    pub fn new(signer: CryptoSigner, file_writer: Option<Arc<Mutex<File>>>) -> Self {
        // Description: Executes the new logic.
        Self {
            signer,
            file_writer,
        }
    }

    pub fn log(&self, session_id: &str, event_type: &str, details: serde_json::Value) {
        // Description: Executes the log logic.
        let timestamp = crate::utils::time::now();
        let entry = AuditEntry {
            session_id,
            timestamp,
            event_type,
            details: details.clone(),
        };

        let payload_str = serde_json::to_string(&entry).unwrap_or_default();

        let signature = self.signer.sign(payload_str.as_bytes());

        eprintln!("[AUDIT] {} {}", signature, payload_str);

        if let Some(writer) = &self.file_writer {
            if let Ok(mut file) = writer.lock() {
                let log_entry = serde_json::json!({
                    "signature": signature,
                    "payload": entry
                });
                if let Err(e) = writeln!(file, "{}", log_entry) {
                    error!("Failed to write to audit log file: {}", e);
                }
            } else {
                error!("Failed to acquire audit log file lock");
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
