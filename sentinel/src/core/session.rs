//! Active Session Enum (Protocol Gateway).
//!
//! This module defines the `ActiveSession` enum which holds the specific
//! protocol adapter version negotiated for the current session.
//! It uses static dispatch (enum match) to forward calls, avoiding vtable overhead.

use crate::core::events::{SecurityDecision, SecurityEvent};
use crate::core::models::{JsonRpcRequest, JsonRpcResponse};
use crate::core::traits::McpSessionHandler;
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
