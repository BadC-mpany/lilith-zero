// Copyright 2026 BadCompany
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::engine_core::crypto::CryptoSigner;
use serde::Serialize;
use tracing::info;

#[derive(Serialize)]
struct AuditEntry<'a> {
    session_id: &'a str,
    timestamp: f64,
    event_type: &'a str,
    details: serde_json::Value,
}

pub struct AuditLogger {
    signer: CryptoSigner,
}

impl AuditLogger {
    pub fn new(signer: CryptoSigner) -> Self {
        Self { signer }
    }

    pub fn log(&self, session_id: &str, event_type: &str, details: serde_json::Value) {
        let timestamp = crate::utils::time::now();
        let entry = AuditEntry {
            session_id,
            timestamp,
            event_type,
            details: details.clone(),
        };

        // Canonicalize JSON for consistent signing
        let payload_str = serde_json::to_string(&entry).unwrap_or_default();

        // Sign the payload
        let signature = self.signer.sign(payload_str.as_bytes());

        // Emit structured log with signature
        info!(
            target: "audit",
            signature = %signature,
            payload = %payload_str,
            "SECURE_AUDIT_LOG"
        );
    }
}
