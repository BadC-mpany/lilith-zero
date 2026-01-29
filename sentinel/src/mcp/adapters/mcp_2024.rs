//! MCP 2024 Protocol Adapter.
//!
//! Implements the 2024-11-05 version of the Model Context Protocol.

use crate::constants::session;
use crate::core::events::{SecurityEvent, SecurityDecision, OutputTransform};
use crate::mcp::adapter::ProtocolAdapter;
use crate::mcp::transport::{JsonRpcRequest, JsonRpcResponse};
use crate::mcp::security::SecurityEngine;
use serde_json::Value;

pub struct Mcp2024Adapter;

impl ProtocolAdapter for Mcp2024Adapter {
    fn version(&self) -> &'static str {
        "2024-11-05"
    }

    fn parse_request(&self, req: &JsonRpcRequest) -> SecurityEvent {
        match req.method.as_str() {
            "initialize" => {
                let params = req.params.as_ref().cloned().unwrap_or(Value::Null);
                let client_info = params.get("clientInfo").cloned().unwrap_or(Value::Null);
                let capabilities = params.get("capabilities").cloned().unwrap_or(Value::Null);
                
                SecurityEvent::Handshake {
                    protocol_version: self.version().to_string(),
                    client_info,
                    audience_token: None, // Not standard in 2024 spec
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
                    tool_name,
                    arguments,
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
                     uri,
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
        match decision {
            SecurityDecision::AllowWithTransforms { output_transforms, .. } => {
                 if let Some(result) = response.result.as_mut() {
                     for transform in output_transforms {
                         match transform {
                             OutputTransform::Spotlight { .. } => {
                                 // Apply spotlighting to standard 2024 content locations.
                                 // NOTE: This implementation aggressively spotlights the entire text field
                                 // and currently ignores the specific `json_paths` provided in the OutputTransform.
                                 // This is a "Defense in Depth" choice for MVP: better to over-spotlight than miss a path.
                                 // Future optimization: Use a JSON pointer walker to target specific paths.
                                 
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
                             _ => {}
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
