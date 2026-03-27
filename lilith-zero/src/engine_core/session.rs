// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and


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
        // Description: Executes the version logic.
        match self {
            Self::V2024(s) => s.version(),
            Self::V2025(s) => s.version(),
        }
    }

    fn parse_request(&self, req: &JsonRpcRequest) -> SecurityEvent {
        // Description: Executes the parse_request logic.
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
        // Description: Executes the apply_decision logic.
        match self {
            Self::V2024(s) => s.apply_decision(decision, response),
            Self::V2025(s) => s.apply_decision(decision, response),
        }
    }

    fn extract_session_token(&self, req: &JsonRpcRequest) -> Option<String> {
        // Description: Executes the extract_session_token logic.
        match self {
            Self::V2024(s) => s.extract_session_token(req),
            Self::V2025(s) => s.extract_session_token(req),
        }
    }

    fn sanitize_for_upstream(&self, req: &mut JsonRpcRequest) {
        // Description: Executes the sanitize_for_upstream logic.
        match self {
            Self::V2024(s) => s.sanitize_for_upstream(req),
            Self::V2025(s) => s.sanitize_for_upstream(req),
        }
    }
}
