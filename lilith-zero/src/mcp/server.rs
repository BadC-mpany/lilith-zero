// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::mcp::codec::McpCodec;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::codec::Encoder;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::engine_core::constants::{jsonrpc, session};
use crate::engine_core::crypto::CryptoSigner;
use crate::engine_core::events::{SecurityDecision, SecurityEvent};
use crate::engine_core::models::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use crate::engine_core::security_core::SecurityCore;
use crate::engine_core::session::ActiveSession;
use crate::engine_core::traits::McpSessionHandler;
use crate::mcp::pipeline::{self, DownstreamEvent, UpstreamEvent};
use crate::mcp::process::ProcessSupervisor;
use crate::protocol::negotiation::HandshakeManager;

pub struct McpMiddleware {
    upstream_cmd: String,
    upstream_args: Vec<String>,
    core: SecurityCore,
    session: ActiveSession,

    upstream_stdin: Option<Box<dyn AsyncWrite + Unpin + Send>>,
    pending_decisions: HashMap<String, SecurityDecision>, // Map Request ID (String) -> Decision

    upstream_supervisor: Option<ProcessSupervisor>,
}

impl McpMiddleware {
    pub fn new(
        upstream_cmd: String,
        upstream_args: Vec<String>,
        config: Arc<Config>,
        audit_log_path: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        // Description: Executes the new logic.
        let signer =
            CryptoSigner::try_new().map_err(|e| anyhow::anyhow!("Crypto init failed: {}", e))?;
        let core = SecurityCore::new(config.clone(), signer, audit_log_path)
            .map_err(|e| anyhow::anyhow!("Security Core init failed: {}", e))?;
        let session = HandshakeManager::negotiate(&config.mcp_version);

        Ok(Self {
            upstream_cmd,
            upstream_args,
            core,
            session,
            upstream_stdin: None,
            pending_decisions: HashMap::new(),
            upstream_supervisor: None,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // Description: Executes the run logic.
        eprintln!("{}{}", session::SESSION_ID_ENV_PREFIX, self.core.session_id);

        info!(
            "lilith-zero Middleware v3 (Actor Model) started. Session: {}",
            self.core.session_id
        );
        eprintln!(
            "lilith-zero Middleware v{} (Session: {})",
            env!("CARGO_PKG_VERSION"),
            self.core.session_id
        );

        if let Some(ref path) = self.core.config.policies_yaml_path {
            match std::fs::read_to_string(path.as_path()) {
                Ok(content) => match serde_yaml::from_str(&content) {
                    Ok(p) => {
                        info!("Loaded policy from {}", path.display());
                        self.core.set_policy(p);
                    }
                    Err(e) => error!("Failed to parse policy YAML: {}", e),
                },
                Err(e) => error!("Failed to read policy file: {}", e),
            }
        } else {
            warn!("No policy loaded. lilith-zero defaults to strict DENY-ALL behavior (unless SecurityLevel::AuditOnly is set).");
        }

        let (tx_downstream_events, mut rx_downstream_events) = mpsc::channel(32);
        let (tx_upstream_events, mut rx_upstream_events) = mpsc::channel(32);

        pipeline::spawn_downstream_reader(tokio::io::stdin(), tx_downstream_events);

        let mut downstream_writer = tokio::io::stdout();

        loop {
            tokio::select! {
                event = rx_downstream_events.recv() => {
                    match event {
                        Some(DownstreamEvent::Request(mut req)) => {
                            debug!("Main Loop: Received Downstream Request: {:?}", req.id);
                            self.handle_client_request(&mut req, &mut downstream_writer, &tx_upstream_events).await?;
                        }
                        Some(DownstreamEvent::Disconnect) => {
                            info!("Client disconnected. Shutting down.");
                            break;
                        }
                        Some(DownstreamEvent::Error(e)) => {
                            warn!("Downstream transport error: {}", e);
                            let _ = self.write_error(
                                &mut downstream_writer,
                                serde_json::Value::Null,
                                jsonrpc::ERROR_PARSE,
                                &e,
                            ).await;

                            if e.contains("exceeds max limit") {
                                use serde_json::json;
                                self.core.log_audit("TRANSPORT_ERROR", json!({
                                    "error": e,
                                    "reason": "Payload too large (DoS attempt)",
                                    "action": "BLOCK_CONNECTION"
                                }));
                            }
                        }
                        None => break, // Channel closed
                    }
                }

                event = rx_upstream_events.recv() => {
                    match event {
                        Some(UpstreamEvent::Response(resp)) => {
                            debug!("Main Loop: Received Upstream Response: {:?}", resp.id);
                            self.handle_upstream_response(resp, &mut downstream_writer).await?;
                        }
                        Some(UpstreamEvent::Log(msg)) => {
                            info!("[Upstream Log] {}", msg);
                        }
                        Some(UpstreamEvent::Terminated(code)) => {
                            warn!("Upstream process terminated (Exit Code: {:?}).", code);
                            self.upstream_stdin = None;
                            self.upstream_supervisor = None;

                            let ids_to_fail: Vec<String> = self.pending_decisions.keys().cloned().collect();
                            for id_str in ids_to_fail {
                                self.pending_decisions.remove(&id_str);
                                let id_val = if let Ok(n) = id_str.parse::<i64>() {
                                    serde_json::Value::Number(n.into())
                                } else {
                                    serde_json::Value::String(id_str)
                                };

                                let _ = self.write_error(
                                    &mut downstream_writer,
                                    id_val,
                                    jsonrpc::ERROR_INTERNAL,
                                    "Upstream process terminated before responding",
                                ).await;
                            }
                        }
                        None => {
                        }
                    }
                }

                _ = tokio::signal::ctrl_c() => {
                    info!("Received Ctrl+C, shutting down.");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_client_request(
        &mut self,
        req: &mut JsonRpcRequest,
        writer: &mut tokio::io::Stdout,
        tx_upstream_events: &mpsc::Sender<UpstreamEvent>,
    ) -> Result<()> {
        // Description: Executes the handle_client_request logic.
        #[cfg(feature = "telemetry")]
        if let Some(params) = &req.params {
            let mut baggage = lilith_telemetry::baggage::current();
            let mut modified = false;

            if let Some(hi) = params.get("_lilith_trace_id_hi").and_then(|v| v.as_u64()) {
                if let Some(lo) = params.get("_lilith_trace_id_lo").and_then(|v| v.as_u64()) {
                    baggage.trace_id = lilith_telemetry::TraceId(hi, lo);
                    modified = true;
                }
            }

            if let Some(parent_sid) = params
                .get("_lilith_parent_span_id")
                .and_then(|v| v.as_u64())
            {
                baggage.span_id = lilith_telemetry::SpanId(parent_sid);
                modified = true;
            }

            if modified {
                lilith_telemetry::baggage::set_current(baggage);
            }
        }

        #[cfg(feature = "telemetry")]
        let _span =
            lilith_telemetry::telemetry_span!("mcp_request", lilith_telemetry::SpanKind::Server);

        let security_event = self.session.parse_request(req);

        let decision = self.core.evaluate(security_event.clone()).await;

        match decision {
            SecurityDecision::Deny { error_code, reason } => {
                warn!("Blocked request: {}", reason);
                if let Some(id) = &req.id {
                    self.write_error(writer, id.clone(), error_code, &reason)
                        .await?;
                }
            }
            SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {
                if let SecurityEvent::Handshake {
                    protocol_version, ..
                } = &security_event
                {
                    if protocol_version != self.session.version() {
                        info!(
                            "Negotiating protocol: Client requested {}, upgrading session.",
                            protocol_version
                        );
                        self.session = HandshakeManager::negotiate(protocol_version);
                    }

                    if self.upstream_stdin.is_none() {
                        if let Err(e) = self.spawn_upstream(tx_upstream_events.clone()).await {
                            error!("Failed to spawn upstream: {}", e);
                            if let Some(id) = &req.id {
                                self.write_error(
                                    writer,
                                    id.clone(),
                                    jsonrpc::ERROR_INTERNAL,
                                    "Failed to start upstream process",
                                )
                                .await?;
                            }
                            return Ok(());
                        }
                    }
                }

                if let Some(id) = &req.id {
                    if let Some(id_str) = id.as_str() {
                        self.pending_decisions
                            .insert(id_str.to_string(), decision.clone());
                    } else if let Some(id_num) = id.as_i64() {
                        self.pending_decisions
                            .insert(id_num.to_string(), decision.clone());
                    }
                }

                if self.upstream_stdin.is_some() {
                    #[cfg(feature = "telemetry")]
                    lilith_telemetry::telemetry_event!(
                        lilith_telemetry::dispatcher::EventLevel::RoutineAllow,
                        format!("Forwarding {} to upstream", req.method).as_bytes()
                    );
                    self.session.sanitize_for_upstream(req);
                    let clean_req = crate::engine_core::taint::Clean::new_unchecked(&*req);
                    self.write_upstream(clean_req).await?;
                } else if let Some(id) = &req.id {
                    self.write_error(
                        writer,
                        id.clone(),
                        jsonrpc::ERROR_METHOD_NOT_FOUND,
                        "Upstream not connected",
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_upstream_response(
        &mut self,
        resp: JsonRpcResponse,
        writer: &mut tokio::io::Stdout,
    ) -> Result<()> {
        // Description: Executes the handle_upstream_response logic.
        #[cfg(feature = "telemetry")]
        let _span =
            lilith_telemetry::telemetry_span!("mcp_response", lilith_telemetry::SpanKind::Server);

        let mut decision = SecurityDecision::Allow; // Default if unsolicited (notifications)?

        let id_key = if let Some(id_str) = resp.id.as_str() {
            Some(id_str.to_string())
        } else {
            resp.id.as_i64().map(|id_num| id_num.to_string())
        };

        if let Some(key) = id_key {
            if let Some(d) = self.pending_decisions.remove(&key) {
                decision = d;
            } else if !resp.id.is_null() {
                warn!(
                    "Received upstream response with unknown ID: {:?}. Dropping.",
                    resp.id
                );
                return Ok(());
            }
        }

        #[cfg(feature = "telemetry")]
        lilith_telemetry::telemetry_event!(
            lilith_telemetry::dispatcher::EventLevel::RoutineAllow,
            b"Forwarding response to client"
        );

        let secured_resp = self.session.apply_decision(&decision, resp);

        let mut codec = McpCodec::new();
        let mut dst = bytes::BytesMut::new();
        codec.encode(&secured_resp, &mut dst)?;
        writer.write_all(&dst).await?;
        writer.flush().await?;

        Ok(())
    }

    async fn spawn_upstream(&mut self, tx_upstream: mpsc::Sender<UpstreamEvent>) -> Result<()> {
        // Description: Executes the spawn_upstream logic.
        info!(
            "Spawning upstream: {} {:?}",
            self.upstream_cmd, self.upstream_args
        );

        let (supervisor, stdin, stdout, stderr) =
            ProcessSupervisor::spawn(&self.upstream_cmd, &self.upstream_args, tx_upstream.clone())
                .context("Failed to spawn upstream")?;

        self.upstream_stdin = stdin;

        if let Some(stdout) = stdout {
            pipeline::spawn_upstream_reader(stdout, tx_upstream.clone());
        }

        if let Some(stderr) = stderr {
            pipeline::spawn_upstream_stderr_drain(stderr, tx_upstream.clone());
        }

        self.upstream_supervisor = Some(supervisor);
        Ok(())
    }

    async fn write_upstream(
        &mut self,
        req: crate::engine_core::taint::Clean<&JsonRpcRequest>,
    ) -> Result<()> {
        // Description: Executes the write_upstream logic.
        if let Some(stdin) = self.upstream_stdin.as_mut() {
            let mut codec = McpCodec::new();
            let mut dst = bytes::BytesMut::new();
            codec.encode(*req, &mut dst)?;
            debug!("Writing {} bytes to upstream", dst.len());
            stdin.write_all(&dst).await?;
            stdin.flush().await?;
        }
        Ok(())
    }

    async fn write_error(
        &self,
        writer: &mut tokio::io::Stdout,
        id: Value,
        code: i32,
        message: &str,
    ) -> Result<()> {
        // Description: Executes the write_error logic.
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
        let mut codec = McpCodec::new();
        let mut dst = bytes::BytesMut::new();
        codec.encode(&response, &mut dst)?;
        writer.write_all(&dst).await?;
        writer.flush().await?;
        Ok(())
    }
}
