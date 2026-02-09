// Copyright 2026 BadCompany
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! JSON-RPC 2.0 transport for MCP.
//!
//! This module provides the `StdioTransport` for reading and writing
//! MCP messages over standard I/O, as well as the core JSON-RPC types.

use anyhow::{Context, Result};

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Stdin, Stdout};
use tracing::debug;

use crate::engine_core::models::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};

pub struct StdioTransport {
    reader: BufReader<Stdin>,
    writer: Stdout,
}

impl Default for StdioTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl StdioTransport {
    pub fn new() -> Self {
        Self {
            reader: BufReader::new(tokio::io::stdin()),
            writer: tokio::io::stdout(),
        }
    }

    /// Read the next JSON-RPC message from Stdin.
    /// Uses a bounded read to prevent DoS attacks via huge lines.
    pub async fn read_message(&mut self) -> Result<Option<JsonRpcRequest>> {
        use crate::engine_core::constants::limits;

        let mut buf = Vec::new();
        // read_until reads until the delimiter is found or EOF
        let bytes_read = self.reader.read_until(b'\n', &mut buf).await?;

        if bytes_read == 0 {
            return Ok(None); // EOF
        }

        if bytes_read as u64 > limits::MAX_MESSAGE_SIZE_BYTES {
            return Err(anyhow::anyhow!(
                "Message exceeded size limit of {} bytes",
                limits::MAX_MESSAGE_SIZE_BYTES
            ));
        }

        let line = String::from_utf8(buf).context("Invalid UTF-8 in request")?;
        debug!("Received: {}", line.trim());

        let req: JsonRpcRequest =
            serde_json::from_str(&line).context("Failed to parse JSON-RPC request")?;
        Ok(Some(req))
    }

    /// Write a JSON-RPC response to Stdout.
    pub async fn write_response(&mut self, response: JsonRpcResponse) -> Result<()> {
        let json = serde_json::to_string(&response).context("Failed to serialize response")?;
        debug!("Sending: {}", json);

        self.writer.write_all(json.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Write a generic error response.
    pub async fn write_error(&mut self, id: Value, code: i32, message: &str) -> Result<()> {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
            id,
        };
        self.write_response(response).await
    }
}
