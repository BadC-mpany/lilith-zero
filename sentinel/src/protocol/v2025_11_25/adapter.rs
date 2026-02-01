//! MCP 2025 Protocol Adapter.
//!
//! Implements support for the 2025-06-18 version of the Model Context Protocol.
//! This includes support for structured tool output and enhanced resource security.

use crate::core::constants::session;
use crate::core::events::{SecurityEvent, SecurityDecision, OutputTransform};
use crate::core::traits::McpSessionHandler;
use crate::core::models::{JsonRpcRequest, JsonRpcResponse};
use crate::utils::security::SecurityEngine;
use serde_json::Value;

#[derive(Debug)]
pub struct Mcp2025Adapter;

impl Mcp2025Adapter {
    pub fn new() -> Self {
        Self
    }
}

impl McpSessionHandler for Mcp2025Adapter {
    fn version(&self) -> &'static str {
        "2025-06-18"
    }

    fn parse_request(&self, req: &JsonRpcRequest) -> SecurityEvent {
        // For MVP, logic is identical to 2024, but would eventually handle
        // "elicitation" requests (server-initiated queries).
        match req.method.as_str() {
             "initialize" => {
                let params = req.params.as_ref().cloned().unwrap_or(Value::Null);
                let client_info = params.get("clientInfo").cloned().unwrap_or(Value::Null);
                let capabilities = params.get("capabilities").cloned().unwrap_or(Value::Null);
                let audience_token = params.get("_audience_token").and_then(|v| v.as_str()).map(|s| s.to_string());
                SecurityEvent::Handshake {
                    protocol_version: self.version().to_string(),
                    client_info,
                    audience_token, // 2025 spec adds formal OAuth, so we'd extract bearer token here.
                    capabilities,
                }
            },
            "tools/call" => {
                // Same as 2024 for now
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
            _ => SecurityEvent::Passthrough {
                request_id: req.id.clone(),
                method: req.method.clone(),
                params: req.params.clone(),
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
                                 // 2025 Spec adds "structuredContent". 
                                 if let Some(structured) = result.get_mut("structuredContent") {
                                     self.recursive_spotlight(structured);
                                 }
                                 
                                 // Backward compatibility with "content"
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

impl Mcp2025Adapter {
    fn recursive_spotlight(&self, value: &mut Value) {
        match value {
            Value::String(s) => {
                 *s = SecurityEngine::spotlight(s);
            },
            Value::Array(arr) => {
                for item in arr {
                    self.recursive_spotlight(item);
                }
            },
            Value::Object(map) => {
                for (k, v) in map {
                    if k == "text" || k == "message" || k == "content" || k == "summary" {
                        if let Value::String(s) = v {
                            *s = SecurityEngine::spotlight(s);
                        } else {
                            self.recursive_spotlight(v);
                        }
                    } else if v.is_object() || v.is_array() {
                         self.recursive_spotlight(v);
                    }
                }
            },
            _ => {}
        }
    }
}
