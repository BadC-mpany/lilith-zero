use tokio::io::{AsyncRead, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error};


use crate::core::models::{JsonRpcRequest, JsonRpcResponse};


/// Messages arriving from the Downstream Client (the Agent)
#[derive(Debug)]
pub enum DownstreamEvent {
    Request(JsonRpcRequest),
    /// Client disconnected (EOF) or explicit shutdown
    Disconnect,
    /// Malformed JSON or Protocol Error
    Error(String),
}

#[derive(Debug)]
pub enum UpstreamEvent {
    Response(JsonRpcResponse),
    /// Unstructured log line from stderr
    Log(String),
    /// Process terminated with optional exit code
    Terminated(Option<i32>),
}

/// Spawns a background task to read from Client Stdin
use tokio_util::codec::FramedRead;
use crate::mcp::codec::McpCodec;
use futures_util::StreamExt; // We need this for .next() on FramedRead

pub fn spawn_downstream_reader(
    stream: tokio::io::Stdin,
    tx: mpsc::Sender<DownstreamEvent>,
) {
    tokio::spawn(async move {
        let mut framed = FramedRead::new(stream, McpCodec::new());
        
        while let Some(result) = framed.next().await {
            match result {
                Ok(val) => {
                    match serde_json::from_value::<JsonRpcRequest>(val) {
                        Ok(req) => {
                            if tx.send(DownstreamEvent::Request(req)).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            error!("JSON-RPC Request parse error: {}", e);
                            let _ = tx.send(DownstreamEvent::Error(e.to_string())).await;
                        }
                    }
                }
                Err(e) => {
                    error!("Framing error: {}", e);
                    let _ = tx.send(DownstreamEvent::Error(e.to_string())).await;
                }
            }
        }
        let _ = tx.send(DownstreamEvent::Disconnect).await;
    });
}


/// Spawns a background task to read from Upstream Stdout (using McpCodec for framing)
pub fn spawn_upstream_reader<R>(
    stream: R,
    tx: mpsc::Sender<UpstreamEvent>,
) where 
    R: AsyncRead + Unpin + Send + 'static 
{
    tokio::spawn(async move {
        let mut framed = FramedRead::new(stream, McpCodec::new());
        
        while let Some(result) = framed.next().await {
            match result {
                Ok(val) => {
                    // Try to parse as JSON-RPC Response
                    match serde_json::from_value::<JsonRpcResponse>(val) {
                        Ok(resp) => {
                            if tx.send(UpstreamEvent::Response(resp)).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("Upstream non-JSON-RPC response: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Upstream framing error: {}", e);
                    break;
                }
            }
        }
    });
}

/// Spawns a background task to drain Upstream Stderr (Log Forwarding)
pub fn spawn_upstream_stderr_drain<R>(
    stream: R,
    tx: mpsc::Sender<UpstreamEvent>,
) where
    R: AsyncRead + Unpin + Send + 'static 
{
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // Pipe closed
                Ok(_) => {
                    let log_msg = line.trim().to_string();
                    if !log_msg.is_empty() {
                         let _ = tx.send(UpstreamEvent::Log(log_msg)).await;
                    }
                }
                Err(_) => break,
            }
        }
    });
}
