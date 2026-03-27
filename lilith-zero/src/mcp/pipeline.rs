// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error};

use crate::engine_core::models::{JsonRpcRequest, JsonRpcResponse};

#[derive(Debug)]
pub enum DownstreamEvent {
    Request(JsonRpcRequest),
    Disconnect,
    Error(String),
}

#[derive(Debug)]
pub enum UpstreamEvent {
    Response(JsonRpcResponse),
    Log(String),
    Terminated(Option<i32>),
}

use crate::mcp::codec::McpCodec;
use futures_util::StreamExt;
use tokio_util::codec::FramedRead; // We need this for .next() on FramedRead

pub fn spawn_downstream_reader(stream: tokio::io::Stdin, tx: mpsc::Sender<DownstreamEvent>) {
    // Description: Executes the spawn_downstream_reader logic.
    tokio::spawn(async move {
        let mut framed = FramedRead::new(stream, McpCodec::new());

        while let Some(result) = framed.next().await {
            match result {
                Ok(val) => match serde_json::from_value::<JsonRpcRequest>(val) {
                    Ok(req) => {
                        if tx.send(DownstreamEvent::Request(req)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("JSON-RPC Request parse error: {}", e);
                        let _ = tx.send(DownstreamEvent::Error(e.to_string())).await;
                    }
                },
                Err(e) => {
                    error!("Framing error: {}", e);
                    let _ = tx.send(DownstreamEvent::Error(e.to_string())).await;
                    break;
                }
            }
        }
        let _ = tx.send(DownstreamEvent::Disconnect).await;
    });
}

pub fn spawn_upstream_reader<R>(stream: R, tx: mpsc::Sender<UpstreamEvent>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    // Description: Executes the spawn_upstream_reader logic.
    tokio::spawn(async move {
        let mut framed = FramedRead::new(stream, McpCodec::new());

        while let Some(result) = framed.next().await {
            match result {
                Ok(val) => {
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

pub fn spawn_upstream_stderr_drain<R>(stream: R, tx: mpsc::Sender<UpstreamEvent>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    // Description: Executes the spawn_upstream_stderr_drain logic.
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
