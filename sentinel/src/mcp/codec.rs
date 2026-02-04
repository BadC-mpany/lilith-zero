//! MCP Transport Codec.
//!
//! Handles the low-level framing of JSON-RPC messages.
//! Supports both standard JSON-RPC (newline delimited) and LSP-style
//! Content-Length headers for robust message framing.

use anyhow::{Result, anyhow, Context};
use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use serde_json::Value;
use tracing::{trace, debug, error};
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
    type Item = Value; // Changed to Value to be more generic for both Req/Resp
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        trace!("Decoder attempting to read from {} bytes buffer", src.len());
        loop {
            match self.state {
                DecodeState::Head => {
                    let mut i = 0;
                    let mut found_header = false;
                    
                    // Robust header parsing: scan for \r\n\r\n or \n\n
                    while i < src.len() {
                        if src[i] == b'\n' {
                            if i >= 1 && src[i-1] == b'\n' {
                                // \n\n case
                                found_header = true;
                                i += 1;
                                break;
                            }
                            if i >= 3 && src[i-1] == b'\r' && src[i-2] == b'\n' && src[i-3] == b'\r' {
                                // \r\n\r\n case
                                found_header = true;
                                i += 1;
                                break;
                            }
                        }
                        i += 1;
                    }

                    if found_header {
                        let header_bytes = src.split_to(i);
                        let header_str = std::str::from_utf8(&header_bytes).context("Invalid UTF-8 in headers")?;
                        
                        let mut len = 0;
                        for line in header_str.lines() {
                            if line.to_lowercase().starts_with("content-length:") {
                                let parts: Vec<&str> = line.split(':').collect();
                                if parts.len() == 2 {
                                    len = parts[1].trim().parse::<usize>().context("Invalid content-length value")?;
                                    debug!("Found Content-Length: {}", len);
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
                        if src.len() > 4096 {
                             return Err(anyhow!("Header too large"));
                        }
                        return Ok(None);
                    }
                }
                DecodeState::Body(len) => {
                    if src.len() >= len {
                        let body = src.split_to(len);
                        self.state = DecodeState::Head;
                        let val: Value = serde_json::from_slice(&body)?;
                        trace!("Decoded message: {:?}", val);
                        return Ok(Some(val));
                    } else {
                        return Ok(None);
                    }
                }
            }
        }
    }
}

// Unified Encoder for both Request and Response
impl Encoder<JsonRpcRequest> for McpCodec {
    type Error = anyhow::Error;
    fn encode(&mut self, item: JsonRpcRequest, dst: &mut BytesMut) -> Result<()> {
        let body = serde_json::to_vec(&item)?;
        let header = format!("Content-Length: {}\r\n\r\n", body.len());
        dst.extend_from_slice(header.as_bytes());
        dst.extend_from_slice(&body);
        Ok(())
    }
}

impl Encoder<JsonRpcResponse> for McpCodec {
    type Error = anyhow::Error;
    fn encode(&mut self, item: JsonRpcResponse, dst: &mut BytesMut) -> Result<()> {
        let body = serde_json::to_vec(&item)?;
        let header = format!("Content-Length: {}\r\n\r\n", body.len());
        dst.extend_from_slice(header.as_bytes());
        dst.extend_from_slice(&body);
        Ok(())
    }
}
