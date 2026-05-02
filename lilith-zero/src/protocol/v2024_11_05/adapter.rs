// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::engine_core::constants::session;
use crate::engine_core::events::{SecurityDecision, SecurityEvent};
use crate::engine_core::models::{JsonRpcRequest, JsonRpcResponse};
use crate::engine_core::taint::Tainted;
use crate::engine_core::traits::McpSessionHandler;
use crate::engine_core::types::TaintedString;
use serde_json::Value;
use tracing::debug;

/// MCP protocol adapter for the `2024-11-05` specification revision.
#[derive(Debug)]
pub struct Mcp2024Adapter;

impl Default for Mcp2024Adapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Mcp2024Adapter {
    /// Create a new [`Mcp2024Adapter`].
    pub fn new() -> Self {
        Self
    }
}

impl McpSessionHandler for Mcp2024Adapter {
    fn version(&self) -> &'static str {
        "2024-11-05"
    }

    fn parse_request(&self, req: &JsonRpcRequest) -> SecurityEvent {
        match req.method.as_str() {
            "initialize" => {
                let params = req.params.as_ref().cloned().unwrap_or(Value::Null);
                let client_info = params.get("clientInfo").cloned().unwrap_or(Value::Null);
                let capabilities = params.get("capabilities").cloned().unwrap_or(Value::Null);
                let audience_token = params
                    .get("_audience_token")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                SecurityEvent::Handshake {
                    protocol_version: self.version().to_string(),
                    client_info,
                    audience_token,
                    capabilities,
                }
            }
            "tools/call" => {
                let params = req
                    .params
                    .as_ref()
                    .cloned()
                    .unwrap_or(Value::Object(serde_json::Map::new()));
                let tool_name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
                let session_token = self.extract_session_token(req);
                let request_id = req.id.clone().unwrap_or(Value::Null);

                SecurityEvent::ToolRequest {
                    request_id,
                    tool_name: TaintedString::new(tool_name),
                    arguments: Tainted::new(arguments, vec![]),
                    session_token,
                }
            }
            "ping" | "notifications/initialized" => SecurityEvent::Passthrough {
                request_id: req.id.clone(),
                method: req.method.clone(),
                params: req.params.clone(),
            },
            "resources/read" => {
                let params = req
                    .params
                    .as_ref()
                    .cloned()
                    .unwrap_or(Value::Object(serde_json::Map::new()));
                let uri = params
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let session_token = self.extract_session_token(req);
                let request_id = req.id.clone().unwrap_or(Value::Null);

                SecurityEvent::ResourceRequest {
                    request_id,
                    uri: TaintedString::new(uri),
                    session_token,
                }
            }
            "prompts/get" => {
                let params = req
                    .params
                    .as_ref()
                    .cloned()
                    .unwrap_or(Value::Object(serde_json::Map::new()));
                let prompt_name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
                let session_token = self.extract_session_token(req);
                let request_id = req.id.clone().unwrap_or(Value::Null);

                SecurityEvent::PromptRequest {
                    request_id,
                    prompt_name: TaintedString::new(prompt_name),
                    arguments: Tainted::new(arguments, vec![]),
                    session_token,
                }
            }
            "sampling/createMessage" => {
                let params = req
                    .params
                    .as_ref()
                    .cloned()
                    .unwrap_or(Value::Object(serde_json::Map::new()));
                let messages = params.get("messages").cloned().unwrap_or(Value::Null);
                let session_token = self.extract_session_token(req);
                let request_id = req.id.clone().unwrap_or(Value::Null);

                SecurityEvent::SamplingRequest {
                    request_id,
                    messages: Tainted::new(messages, vec![]),
                    session_token,
                }
            }
            _ => SecurityEvent::Passthrough {
                request_id: req.id.clone(),
                method: req.method.clone(),
                params: req.params.clone(),
            },
        }
    }

    fn apply_decision(
        &self,
        decision: &SecurityDecision,
        response: JsonRpcResponse,
    ) -> JsonRpcResponse {
        debug!("Applying decision to response (id: {:?})", response.id);
        // Future output transforms (e.g. Redact) are applied here.
        // Currently no transforms are applied; the response passes through unchanged.
        let _ = decision;
        response
    }

    fn extract_session_token(&self, req: &JsonRpcRequest) -> Option<String> {
        req.params
            .as_ref()
            .and_then(|p| p.get(session::SESSION_ID_PARAM))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    fn sanitize_for_upstream(&self, req: &mut JsonRpcRequest) {
        if let Some(params) = req.params.as_mut() {
            if let Some(obj) = params.as_object_mut() {
                obj.remove(session::SESSION_ID_PARAM);
            }
        }
    }
}
