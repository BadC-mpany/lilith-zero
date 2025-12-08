// HTTP client for MCP proxying with JSON-RPC 2.0 protocol support

use crate::api::ProxyClient;
use crate::core::errors::InterceptorError;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info};
use uuid::Uuid;
use crate::core::resilience::{SentinelCircuitBreaker, create_circuit_breaker, execute_with_cb};

/// JSON-RPC 2.0 error structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: Option<serde_json::Value>,
}

/// HTTP proxy client for forwarding requests to MCP servers
/// 
/// Uses JSON-RPC 2.0 protocol with connection pooling for performance.
pub struct ProxyClientImpl {
    http_client: Client,
    default_timeout: Duration,
    cb: SentinelCircuitBreaker,
}

impl ProxyClientImpl {
    /// Create a new ProxyClient with connection pooling
    /// 
    /// # Arguments
    /// * `timeout_secs` - Request timeout in seconds (default: 5)
    /// 
    /// # Returns
    /// * `Result<Self, InterceptorError>` - ProxyClient instance or error
    pub fn new(timeout_secs: u64) -> Result<Self, InterceptorError> {
        let timeout = Duration::from_secs(timeout_secs);
        let connect_timeout = Duration::from_secs(2); // Fail fast on connection

        let http_client = Client::builder()
            .timeout(timeout)
            .connect_timeout(connect_timeout)
            .tcp_nodelay(true) // Reduce latency
            .pool_idle_timeout(Duration::from_secs(90)) // Reuse connections
            .build()
            .map_err(|e| InterceptorError::ConfigurationError(format!(
                "Failed to create HTTP client: {}", e
            )))?;

        Ok(Self {
            http_client,
            default_timeout: timeout,
            cb: create_circuit_breaker(),
        })
    }

    /// Map JSON-RPC error code to error message
    pub(crate) fn map_jsonrpc_error(error: &JsonRpcError) -> String {
        let base_msg = match error.code {
            -32700 => "Parse error",
            -32600 => "Invalid request",
            -32601 => "Method not found",
            -32602 => "Invalid params",
            -32603 => "Internal error",
            _ => "Unknown error",
        };

        // Check for auth-related errors in message
        // Check scope/integrity first (authorization) before token/signature (authentication)
        let msg_lower = error.message.to_lowercase();
        if msg_lower.contains("scope") || msg_lower.contains("integrity") {
            format!("Authorization failed: {}", error.message)
        } else if msg_lower.contains("token")
            || msg_lower.contains("signature")
            || msg_lower.contains("replay")
        {
            format!("Authentication failed: {}", error.message)
        } else {
            format!("{}: {}", base_msg, error.message)
        }
    }

    /// Forward request to MCP server using JSON-RPC 2.0 protocol
    async fn forward_request_internal(
        &self,
        url: &str,
        tool_name: &str,
        args: &serde_json::Value,
        session_id: &str,
        callback_url: Option<&str>,
        token: &str,
    ) -> Result<serde_json::Value, InterceptorError> {
        // Generate request ID
        let request_id = Uuid::new_v4().to_string();

        // Construct JSON-RPC 2.0 request
        let jsonrpc_request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args,
                "session_id": session_id,
                "agent_callback_url": callback_url.map(|s| serde_json::Value::String(s.to_string()))
                    .unwrap_or(serde_json::Value::Null)
            },
            "id": request_id
        });

        debug!(
            url = %url,
            tool = %tool_name,
            request_id = %request_id,
            "Forwarding request to MCP server"
        );

        // Send HTTP POST request
        let response = self
            .http_client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token))
            .json(&jsonrpc_request)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    InterceptorError::TransientError(format!("Request timeout after {}s", self.default_timeout.as_secs()))
                } else if e.is_connect() {
                    InterceptorError::DependencyFailure { 
                        service: "MCP Agent".to_string(), 
                        error: "Connection failed".to_string() 
                    }
                } else {
                    InterceptorError::McpProxyError(format!("HTTP request failed: {}", e))
                }
            })?;

        // Check HTTP status
        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            error!(
                status = %status,
                url = %url,
                error = %error_text,
                "MCP server returned HTTP error"
            );
            return Err(InterceptorError::McpProxyError(format!("MCP server error: HTTP {} - {}", status, error_text)));
        }

        // Parse JSON-RPC 2.0 response
        let jsonrpc_response: JsonRpcResponse = response
            .json()
            .await
            .map_err(|e| {
                error!(error = %e, url = %url, "Failed to parse JSON-RPC response");
                InterceptorError::McpProxyError(format!("Failed to parse response: {}", e))
            })?;

        // Validate JSON-RPC version
        if jsonrpc_response.jsonrpc != "2.0" {
            error!(
                jsonrpc = %jsonrpc_response.jsonrpc,
                url = %url,
                "Invalid JSON-RPC version"
            );
            return Err(InterceptorError::McpProxyError(format!(
                "Invalid JSON-RPC version: {}",
                jsonrpc_response.jsonrpc
            )));
        }

        // Handle JSON-RPC error response
        if let Some(error) = jsonrpc_response.error {
            let error_msg = Self::map_jsonrpc_error(&error);
            error!(
                code = error.code,
                message = %error.message,
                url = %url,
                "MCP server returned JSON-RPC error"
            );
            return Err(InterceptorError::McpProxyError(error_msg));
        }

        // Extract result
        match jsonrpc_response.result {
            Some(result) => {
                info!(
                    url = %url,
                    tool = %tool_name,
                    request_id = %request_id,
                    "MCP request completed successfully"
                );
                Ok(result)
            }
            None => {
                error!(
                    url = %url,
                    request_id = ?jsonrpc_response.id,
                    "JSON-RPC response missing result field"
                );
                Err(InterceptorError::McpProxyError("Invalid response from MCP server: missing result field".to_string()))
            }
        }
    }
}

#[async_trait]
impl ProxyClient for ProxyClientImpl {
    async fn forward_request(
        &self,
        url: &str,
        tool_name: &str,
        args: &serde_json::Value,
        session_id: &str,
        callback_url: Option<&str>,
        token: &str,
    ) -> Result<serde_json::Value, InterceptorError> {
        // Clone arguments for the closure (to satisfy 'static or lifetime requirements of async closures)
        // Although failsafe call might support references, cloning ensures safety and simpler lifetimes
        // for these relatively small metadata strings. args (Value) is cloned too.
        let url = url.to_string();
        let tool_name = tool_name.to_string();
        let args = args.clone();
        let session_id = session_id.to_string();
        let callback_url = callback_url.map(|s| s.to_string());
        let token = token.to_string();

        execute_with_cb(&self.cb, || async {
            self.forward_request_internal(
                &url, 
                &tool_name, 
                &args, 
                &session_id, 
                callback_url.as_deref(), 
                &token
            ).await
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_jsonrpc_error_parse_error() {
        let error = JsonRpcError {
            code: -32700,
            message: "Parse error occurred".to_string(),
            data: None,
        };
        let msg = ProxyClientImpl::map_jsonrpc_error(&error);
        assert_eq!(msg, "Parse error: Parse error occurred");
    }

    #[test]
    fn test_map_jsonrpc_error_auth_error() {
        let error = JsonRpcError {
            code: -32600,
            message: "Invalid Signature".to_string(),
            data: None,
        };
        let msg = ProxyClientImpl::map_jsonrpc_error(&error);
        assert!(msg.contains("Authentication failed"));
        assert!(msg.contains("Invalid Signature"));
    }

    #[test]
    fn test_map_jsonrpc_error_scope_error() {
        let error = JsonRpcError {
            code: -32600,
            message: "Token Scope Mismatch".to_string(),
            data: None,
        };
        let msg = ProxyClientImpl::map_jsonrpc_error(&error);
        assert!(msg.contains("Authorization failed"));
    }

    #[test]
    fn test_proxy_client_creation() {
        let client = ProxyClientImpl::new(5).unwrap();
        assert_eq!(client.default_timeout.as_secs(), 5);
    }

    #[test]
    fn test_proxy_client_default_timeout() {
        let client = ProxyClientImpl::new(10).unwrap();
        assert_eq!(client.default_timeout.as_secs(), 10);
    }
}
