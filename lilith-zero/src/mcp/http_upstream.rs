// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

//! HTTP upstream transport for the MCP Streamable HTTP protocol (2025-11-25).
//!
//! Connects Lilith to an upstream MCP server via HTTP instead of a child process.
//! The JSON-RPC body format is identical to stdio; only the framing differs.
//!
//! Session lifecycle:
//! 1. `initialize` is sent **without** `Mcp-Session-Id`.
//! 2. Server responds with `Mcp-Session-Id: <uuid>` in the response headers.
//! 3. All subsequent requests carry that header.
//! 4. On shutdown, `DELETE /mcp` terminates the session (best-effort).

use crate::engine_core::models::{JsonRpcRequest, JsonRpcResponse};
use anyhow::{Context, Result};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::Client;
use tracing::{debug, info, warn};

const MCP_SESSION_HEADER: &str = "Mcp-Session-Id";

/// HTTP client for an upstream MCP Streamable HTTP server.
pub struct HttpUpstream {
    /// Full URL of the upstream `/mcp` endpoint.
    url: String,
    client: Client,
    /// Server-assigned session ID; `None` until the first `initialize` response.
    mcp_session_id: Option<String>,
}

impl HttpUpstream {
    /// Create an `HttpUpstream` for the given URL.
    ///
    /// # Errors
    /// Returns an error if the `reqwest` client cannot be built (e.g. TLS init failure).
    pub fn new(url: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client")?;
        info!("HTTP upstream configured: {}", url);
        Ok(Self {
            url,
            client,
            mcp_session_id: None,
        })
    }

    /// Send a JSON-RPC request to the upstream and return the decoded response.
    ///
    /// Handles both `application/json` (immediate result) and `text/event-stream`
    /// (streaming) response formats.  The `Mcp-Session-Id` is extracted and cached
    /// from the response headers so subsequent calls include it automatically.
    pub async fn send(&mut self, req: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        debug!("HTTP upstream → {}: {:?}", req.method, req.id);

        let mut builder = self
            .client
            .post(&self.url)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json, text/event-stream")
            .json(req);

        if let Some(ref sid) = self.mcp_session_id {
            builder = builder.header(MCP_SESSION_HEADER, sid.as_str());
        }

        let response = builder
            .send()
            .await
            .context("HTTP upstream request failed")?;

        let status = response.status();
        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "HTTP upstream returned non-success status: {status}"
            ));
        }

        // Latch the server-assigned session ID on first response.
        if let Some(sid_hdr) = response.headers().get(MCP_SESSION_HEADER) {
            match sid_hdr.to_str() {
                Ok(sid) => {
                    info!("HTTP upstream session established: {}", sid);
                    self.mcp_session_id = Some(sid.to_string());
                }
                Err(e) => warn!("Ignoring non-UTF8 Mcp-Session-Id header: {}", e),
            }
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if content_type.contains("text/event-stream") {
            self.collect_sse(response).await
        } else {
            response
                .json::<JsonRpcResponse>()
                .await
                .context("Failed to decode HTTP JSON-RPC response")
        }
    }

    /// Send `DELETE /mcp` to terminate the server-side session.  Best-effort; errors
    /// are logged but not propagated — the caller is shutting down regardless.
    pub async fn close(&mut self) {
        let Some(ref sid) = self.mcp_session_id else {
            return;
        };
        debug!("Closing HTTP upstream session: {}", sid);
        let _ = self
            .client
            .delete(&self.url)
            .header(MCP_SESSION_HEADER, sid.as_str())
            .send()
            .await;
        self.mcp_session_id = None;
    }

    /// Collect all SSE frames from a streaming response and return the final
    /// JSON-RPC result frame.
    ///
    /// The MCP spec allows servers to push progress notifications before the
    /// final result.  We return the last parseable `JsonRpcResponse` frame.
    async fn collect_sse(&self, response: reqwest::Response) -> Result<JsonRpcResponse> {
        let body = response
            .text()
            .await
            .context("Failed to read SSE response body")?;

        let mut last: Option<JsonRpcResponse> = None;

        for line in body.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                if data.trim() == "[DONE]" {
                    break;
                }
                if let Ok(msg) = serde_json::from_str::<JsonRpcResponse>(data) {
                    last = Some(msg);
                }
            }
        }

        last.ok_or_else(|| anyhow::anyhow!("SSE stream contained no valid JSON-RPC response"))
    }
}
