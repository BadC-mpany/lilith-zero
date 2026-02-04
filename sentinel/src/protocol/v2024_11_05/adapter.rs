//! MCP 2024 Protocol Adapter.
//!
//! Implements the 2024-11-05 version of the Model Context Protocol.

use crate::core::constants::session;
use crate::core::events::{SecurityEvent, SecurityDecision, OutputTransform};
use crate::core::traits::McpSessionHandler;
use crate::core::models::{JsonRpcRequest, JsonRpcResponse};
use crate::utils::security::SecurityEngine;
use crate::core::types::TaintedString;
use crate::core::taint::Tainted;
use serde_json::Value;
use tracing::debug;

#[derive(Debug)]
pub struct Mcp2024Adapter;

impl Mcp2024Adapter {
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
                let audience_token = params.get("_audience_token").and_then(|v| v.as_str()).map(|s| s.to_string());
                
                SecurityEvent::Handshake {
                    protocol_version: self.version().to_string(),
                    client_info,
                    audience_token, 
                    capabilities,
                }
            },
            "tools/call" => {
                let params = req.params.as_ref().cloned().unwrap_or(Value::Object(serde_json::Map::new()));
                let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
                let session_token = self.extract_session_token(req);
                let request_id = req.id.clone().unwrap_or(Value::Null);

                SecurityEvent::ToolRequest {
                    request_id,
                    tool_name: TaintedString::new(tool_name),
                    arguments: Tainted::new(arguments, vec![]),
                    session_token,
                }
            },
             "ping" | "notifications/initialized" => {
                SecurityEvent::Passthrough {
                    request_id: req.id.clone(),
                    method: req.method.clone(),
                    params: req.params.clone(),
                }
            },
            "resources/read" => {
                 let params = req.params.as_ref().cloned().unwrap_or(Value::Object(serde_json::Map::new()));
                 let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("").to_string();
                 let session_token = self.extract_session_token(req);
                 let request_id = req.id.clone().unwrap_or(Value::Null);

                 SecurityEvent::ResourceRequest {
                     request_id,
                     uri: TaintedString::new(uri),
                     session_token
                 }
            },
            _ => {
                SecurityEvent::Passthrough {
                    request_id: req.id.clone(),
                    method: req.method.clone(),
                    params: req.params.clone(),
                }
            }
        }
    }

    fn apply_decision(
        &self,
        decision: &SecurityDecision,
        mut response: JsonRpcResponse,
    ) -> JsonRpcResponse {
        debug!("Applying decision to response (id: {:?})", response.id);
        match decision {
            SecurityDecision::AllowWithTransforms { output_transforms, .. } => {
                 if let Some(result) = response.result.as_mut() {
                     for transform in output_transforms {
                         if let OutputTransform::Spotlight { .. } = transform {
                             // Apply spotlighting to standard 2024 content locations.
                             // 1. tools/call response: { content: [ { type: "text", text: "..." } ] }
                             if let Some(content) = result.get_mut("content").and_then(|v| v.as_array_mut()) {
                                 for item in content {
                                     if let Some(text_val) = item.get_mut("text") {
                                         if let Some(text) = text_val.as_str() {
                                             let spotlighted = SecurityEngine::spotlight(text);
                                             *text_val = Value::String(spotlighted);
                                         }
                                     }
                                 }
                             }
                             
                             // 2. resources/read response: { contents: [ { uri: "...", text: "..." } ] }
                              if let Some(contents) = result.get_mut("contents").and_then(|v| v.as_array_mut()) {
                                 for item in contents {
                                     if let Some(text_val) = item.get_mut("text") {
                                          if let Some(text) = text_val.as_str() {
                                             let spotlighted = SecurityEngine::spotlight(text);
                                             *text_val = Value::String(spotlighted);
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
                 response
            },
            _ => response,
        }
    }

    fn extract_session_token(&self, req: &JsonRpcRequest) -> Option<String> {
        req.params.as_ref()
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
