//! JSON-RPC 2.0 transport for MCP.
//! 
//! This module provides the `StdioTransport` for reading and writing 
//! MCP messages over standard I/O, as well as the core JSON-RPC types.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Stdin, Stdout};
use anyhow::{Result, Context};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
    pub id: Option<Value>, // Can be number or string. None means notification.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Option<Value>,
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

pub struct StdioTransport {
    reader: BufReader<Stdin>,
    writer: Stdout,
}

impl StdioTransport {
    pub fn new() -> Self {
        Self {
            reader: BufReader::new(tokio::io::stdin()),
            writer: tokio::io::stdout(),
        }
    }

    /// Read the next JSON-RPC message from Stdin.
    pub async fn read_message(&mut self) -> Result<Option<JsonRpcRequest>> {
        let mut line = String::new();
        let bytes = self.reader.read_line(&mut line).await.context("Failed to read from stdin")?;
        
        if bytes == 0 {
            return Ok(None); // EOF
        }

        debug!("Received: {}", line.trim());

        let req: JsonRpcRequest = serde_json::from_str(&line).context("Failed to parse JSON-RPC request")?;
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
