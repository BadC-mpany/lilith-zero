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

//! Handshake Manager (Protocol Negotiation/Factory).
//!
//! Handles the version negotiation logic and initializes the appropriate
//! `ActiveSession` (Protocol Gateway) variant.

use crate::engine_core::session::ActiveSession;
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
