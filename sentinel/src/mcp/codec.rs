//! MCP Transport Codec.
//!
//! Handles the low-level framing of JSON-RPC messages.
//! Supports both standard JSON-RPC (newline delimited) and LSP-style
//! Content-Length headers for robust message framing.

use anyhow::{Result, anyhow, Context};
use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use crate::core::models::{JsonRpcRequest, JsonRpcResponse};
use crate::core::constants::limits;

// State machine for LSP-style headers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeState {
    Head,
    Body(usize),
}

pub struct McpCodec {
    state: DecodeState,
}

impl McpCodec {
    pub fn new() -> Self {
        Self { state: DecodeState::Head }
    }
}

impl Default for McpCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for McpCodec {
    type Item = JsonRpcRequest;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        loop {
            match self.state {
                DecodeState::Head => {
                    // Check for standard newline delimited JSON first (legacy/simple mode)
                    // If line starts with '{', assume NDJSON.
                    if !src.is_empty() && src[0] == b'{' {
                        if let Some(i) = src.iter().position(|&b| b == b'\n') {
                            let line = src.split_to(i + 1);
                            let line = &line[..line.len() - 1]; // strip \n
                            if line.is_empty() { return Ok(None); }
                            
                            let req: JsonRpcRequest = serde_json::from_slice(line)?;
                            return Ok(Some(req));
                        } else {
                            // Wait for more data
                            return Ok(None);
                        }
                    }

                    // Otherwise, look for Content-Length header (LSP style)
                    // "Content-Length: 123\r\n\r\n"
                    let mut i = 0;
                    let mut found_header = false;
                    
                    // Naive header parsing: scan for \r\n\r\n
                    // Windows: \r\n\r\n, Linux: \r\n\r\n or \n\n. strict spec says \r\n.
                    while i + 3 < src.len() {
                        if src[i] == b'\r' && src[i+1] == b'\n' && src[i+2] == b'\r' && src[i+3] == b'\n' {
                             found_header = true;
                             break;
                        }
                        i += 1;
                    }

                    if found_header {
                        let header_bytes = src.split_to(i + 4);
                        let header_str = std::str::from_utf8(&header_bytes).context("Invalid UTF-8 in headers")?;
                        
                        let mut len = 0;
                        for line in header_str.lines() {
                            if line.to_lowercase().starts_with("content-length:") {
                                let parts: Vec<&str> = line.split(':').collect();
                                if parts.len() == 2 {
                                    len = parts[1].trim().parse::<usize>().context("Invalid content-length value")?;
                                }
                            }
                        }

                        if len == 0 {
                            return Err(anyhow!("Missing or invalid Content-Length header"));
                        }
                        
                        if len as u64 > limits::MAX_MESSAGE_SIZE_BYTES {
                             return Err(anyhow!("Message length {} exceeds max limit", len));
                        }

                        self.state = DecodeState::Body(len);
                    } else {
                        // Wait for more data
                        // Check for header limit to prevent DoS
                        if src.len() > 4096 {
                             return Err(anyhow!("Header too large"));
                        }
                        return Ok(None);
                    }
                }
                DecodeState::Body(len) => {
                    if src.len() >= len {
                        let body = src.split_to(len);
                        self.state = DecodeState::Head; // Reset
                        let req: JsonRpcRequest = serde_json::from_slice(&body)?;
                        return Ok(Some(req));
                    } else {
                        return Ok(None); // Wait for body
                    }
                }
            }
        }
    }
}

// Encoder for responses (always NDJSON for now to be simple, or LSP style?)
// Plan says: Enforce Content-Length for INPUT.
// For OUTPUT, we can stick to NDJSON if the client supports it, OR switch to LSP style.
// Best practice: Be strict on input, liberal on output, OR match input style.
// For MCP/LSP, Headers are preferred.
pub struct McpResponseEncoder;

impl Encoder<JsonRpcResponse> for McpResponseEncoder {
    type Error = anyhow::Error;

    fn encode(&mut self, item: JsonRpcResponse, dst: &mut BytesMut) -> Result<()> {
        let body = serde_json::to_vec(&item)?;
        // Write LSP header if needed? Or just NDJSON.
        // Let's stick to NDJSON for the MVP-2 unless strictly required. 
        // "Transport Protocol will be updated to strictly enforce Content-Length... This may require updates to SDK"
        // Let's output NDJSON for compatibility with current SDK. The Codec mostly protects INPUT smuggling.
        dst.extend_from_slice(&body);
        dst.extend_from_slice(b"\n");
        Ok(())
    }
}
