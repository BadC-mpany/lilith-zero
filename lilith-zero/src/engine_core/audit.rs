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
