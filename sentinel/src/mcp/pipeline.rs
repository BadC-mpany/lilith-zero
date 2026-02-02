use tokio::io::{AsyncBufReadExt, BufReader};
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

/// Messages arriving from the Upstream Server (the Tool)
#[derive(Debug)]
pub enum UpstreamEvent {
    Response(JsonRpcResponse),
    /// Unstructured log line from stderr
    Log(String),
    /// Process terminated
    Terminated,
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
                Ok(req) => {
                    if tx.send(DownstreamEvent::Request(req)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("Framing error: {}", e);
                    let _ = tx.send(DownstreamEvent::Error(e.to_string())).await;
                    // If strict, we might break here. Codec helps recovery though.
                    // For now, continue but warn? 
                    // Actually, breaking on error is safer if stream is desynced.
                    // break; 
                }
            }
        }
        // EOF
        let _ = tx.send(DownstreamEvent::Disconnect).await;
    });
}


/// Spawns a background task to read from Upstream Stdout
pub fn spawn_upstream_reader(
    stream: tokio::process::ChildStdout,
    tx: mpsc::Sender<UpstreamEvent>,
) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    let _ = tx.send(UpstreamEvent::Terminated).await;
                    break;
                }
                Ok(_) => {
                    // Try to parse as JSON-RPC Response
                    let trimmed = line.trim();
                    if trimmed.is_empty() { continue; }
                    
                    if trimmed.starts_with('{') {
                         match serde_json::from_str::<JsonRpcResponse>(trimmed) {
                            Ok(resp) => {
                                if tx.send(UpstreamEvent::Response(resp)).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => {
                                // Fallback: Treat as log noise if it looks like JSON but fails, 
                                // or generally just send as noise?
                                // Context says: "Treat... as potentially malicious fuzzing input".
                                // For now, we log it as noise but don't crash.
                                debug!("Upstream non-JSON stdout: {}", trimmed);
                            }
                        }
                    } else {
                        // Plain text noise
                         debug!("Upstream stdout noise: {}", trimmed);
                    }
                }
                Err(e) => {
                    error!("Error reading upstream stdout: {}", e);
                    let _ = tx.send(UpstreamEvent::Terminated).await;
                    break;
                }
            }
        }
    });
}

/// Spawns a background task to drain Upstream Stderr (Log Forwarding)
pub fn spawn_upstream_stderr_drain(
    stream: tokio::process::ChildStderr,
    tx: mpsc::Sender<UpstreamEvent>,
) {
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
