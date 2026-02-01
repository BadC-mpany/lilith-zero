use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};
use serde_json::Value;

use crate::core::models::{JsonRpcRequest, JsonRpcResponse};
use crate::core::constants::limits;

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
pub fn spawn_downstream_reader(
    stream: tokio::io::Stdin,
    tx: mpsc::Sender<DownstreamEvent>,
) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::new();
        
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf).await {
                Ok(0) => {
                    // EOF
                    let _ = tx.send(DownstreamEvent::Disconnect).await;
                    break;
                }
                Ok(n) => {
                    if n as u64 > limits::MAX_MESSAGE_SIZE_BYTES {
                        let _ = tx.send(DownstreamEvent::Error("Message too large".to_string())).await;
                        continue;
                    }
                    
                    let line = String::from_utf8_lossy(&buf);
                     debug!("Processing downstream line: {}", line.trim());
                    // Parse
                    match serde_json::from_slice::<JsonRpcRequest>(&buf) {
                        Ok(req) => {
                             if tx.send(DownstreamEvent::Request(req)).await.is_err() {
                                 break; // Receiver dropped, stop
                             }
                        }
                        Err(e) => {
                             // If it's empty line, ignore.
                             if buf.iter().all(|b| b.is_ascii_whitespace()) {
                                 continue;
                             }
                             warn!("Failed to parse downstream JSON: {}. Line: {:?}", e, line);
                             let _ = tx.send(DownstreamEvent::Error(format!("Parse error: {}", e))).await;
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading downstream stdin: {}", e);
                    let _ = tx.send(DownstreamEvent::Disconnect).await;
                    break;
                }
            }
        }
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
