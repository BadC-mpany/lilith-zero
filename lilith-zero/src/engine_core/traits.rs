// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::engine_core::events::{SecurityDecision, SecurityEvent};
use crate::engine_core::models::{JsonRpcRequest, JsonRpcResponse};

pub trait McpSessionHandler: Send + Sync {
    fn version(&self) -> &'static str;

    /// Parse a raw JSON-RPC request into a generic SecurityEvent.
    fn parse_request(&self, req: &JsonRpcRequest) -> SecurityEvent;

    /// Apply the security decision to the upstream response.
    fn apply_decision(
        &self,
        decision: &SecurityDecision,
        response: JsonRpcResponse,
    ) -> JsonRpcResponse;

    /// Extract the session token from the request headers or parameters.
    fn extract_session_token(&self, req: &JsonRpcRequest) -> Option<String>;

    /// Prepare the request for forwarding to the upstream server.
    fn sanitize_for_upstream(&self, req: &mut JsonRpcRequest);
}
