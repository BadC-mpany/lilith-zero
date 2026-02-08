//! Handshake Manager (Protocol Negotiation/Factory).
//!
//! Handles the version negotiation logic and initializes the appropriate
//! `ActiveSession` (Protocol Gateway) variant.

use crate::core::session::ActiveSession;
use crate::protocol::{v2024_11_05, v2025_11_25};
use tracing::info;

pub struct HandshakeManager;

impl HandshakeManager {
    /// Negotiate the protocol version and return an initialized Session Gateway.
    pub fn negotiate(client_version: &str) -> ActiveSession {
        match client_version {
            "2024-11-05" => {
                info!("Initializing Legacy 2024 Adapter...");
                ActiveSession::V2024(v2024_11_05::adapter::Mcp2024Adapter::new())
            }
            "2025-11-25" | "2025-06-18" | "latest" => {
                info!("Initializing Modern 2025 Adapter...");
                ActiveSession::V2025(v2025_11_25::adapter::Mcp2025Adapter::new())
            }
            _ => {
                info!(
                    "Unknown version '{}', upgrading to 2025-11-25",
                    client_version
                );
                ActiveSession::V2025(v2025_11_25::adapter::Mcp2025Adapter::new())
            }
        }
    }
}
