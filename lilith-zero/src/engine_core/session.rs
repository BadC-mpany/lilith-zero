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

//! Active Session Enum (Protocol Gateway).
//!
//! This module defines the `ActiveSession` enum which holds the specific
//! protocol adapter version negotiated for the current session.
//! It uses static dispatch (enum match) to forward calls, avoiding vtable overhead.

use crate::engine_core::events::{SecurityDecision, SecurityEvent};
use crate::engine_core::models::{JsonRpcRequest, JsonRpcResponse};
use crate::engine_core::traits::McpSessionHandler;
use crate::protocol::{v2024_11_05, v2025_11_25};

#[derive(Debug)]
pub enum ActiveSession {
    V2024(v2024_11_05::adapter::Mcp2024Adapter),
    V2025(v2025_11_25::adapter::Mcp2025Adapter),
}

impl McpSessionHandler for ActiveSession {
    fn version(&self) -> &'static str {
        match self {
            Self::V2024(s) => s.version(),
            Self::V2025(s) => s.version(),
        }
    }

    fn parse_request(&self, req: &JsonRpcRequest) -> SecurityEvent {
        match self {
            Self::V2024(s) => s.parse_request(req),
            Self::V2025(s) => s.parse_request(req),
        }
    }

    fn apply_decision(
        &self,
        decision: &SecurityDecision,
        response: JsonRpcResponse,
    ) -> JsonRpcResponse {
        match self {
            Self::V2024(s) => s.apply_decision(decision, response),
            Self::V2025(s) => s.apply_decision(decision, response),
        }
    }

    fn extract_session_token(&self, req: &JsonRpcRequest) -> Option<String> {
        match self {
            Self::V2024(s) => s.extract_session_token(req),
            Self::V2025(s) => s.extract_session_token(req),
        }
    }

    fn sanitize_for_upstream(&self, req: &mut JsonRpcRequest) {
        match self {
            Self::V2024(s) => s.sanitize_for_upstream(req),
            Self::V2025(s) => s.sanitize_for_upstream(req),
        }
    }
}
