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
use crate::utils::policy_validator::{PolicyValidator, ValidationSeverity};
use crate::engine_core::crypto::CryptoSigner;
use crate::engine_core::events::{SecurityDecision, SecurityEvent};
use crate::engine_core::models::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use crate::engine_core::security_core::SecurityCore;
use crate::engine_core::session::ActiveSession;
use crate::engine_core::traits::McpSessionHandler;
use crate::mcp::pin_store::PinStore;
use crate::mcp::pipeline::{self, DownstreamEvent, UpstreamEvent};
use crate::mcp::process::ProcessSupervisor;
use crate::protocol::negotiation::HandshakeManager;

/// The main MCP security middleware.
///
/// Sits between the AI agent (downstream stdio) and the upstream MCP server (subprocess).
/// Evaluates every request against the security policy before forwarding, and applies
/// output transforms (spotlighting) to responses before returning them to the agent.
pub struct McpMiddleware {
    upstream_cmd: String,
    upstream_args: Vec<String>,
    core: SecurityCore,
    session: ActiveSession,

    upstream_stdin: Option<Box<dyn AsyncWrite + Unpin + Send>>,
    pending_decisions: HashMap<String, SecurityDecision>, // Request ID → Decision
    pending_methods: HashMap<String, String>,             // Request ID → method name

    upstream_supervisor: Option<ProcessSupervisor>,
    pin_store: PinStore,
}

impl McpMiddleware {
    /// Create a new [`McpMiddleware`].
    ///
    /// Initialises the crypto signer and security core.  The upstream process is not spawned
    /// until the first `initialize` handshake is received.
    pub fn new(
        upstream_cmd: String,
        upstream_args: Vec<String>,
        config: Arc<Config>,
        audit_log_path: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        let signer =
            CryptoSigner::try_new().map_err(|e| anyhow::anyhow!("Crypto init failed: {}", e))?;
        let core = SecurityCore::new(config.clone(), signer, audit_log_path)
            .map_err(|e| anyhow::anyhow!("Security Core init failed: {}", e))?;
        let session = HandshakeManager::negotiate(&config.mcp_version);
        let pin_store = PinStore::new(config.pin_mode, config.pin_file.clone())
            .map_err(|e| anyhow::anyhow!("Pin store init failed: {}", e))?;

        Ok(Self {
            upstream_cmd,
            upstream_args,
            core,
            session,
            upstream_stdin: None,
            pending_decisions: HashMap::new(),
            pending_methods: HashMap::new(),
            upstream_supervisor: None,
            pin_store,
        })
    }

    /// Run the middleware event loop until the downstream agent disconnects or Ctrl-C is received.
    pub async fn run(&mut self) -> Result<()> {
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
                Ok(content) => match serde_yaml_ng::from_str(&content) {
                    Ok(p) => {
                        // Structured validation: emit all diagnostics before activating policy.
                        let diagnostics = PolicyValidator::validate_policy_detailed(&p);
                        let has_errors = diagnostics
                            .iter()
                            .any(|d| d.severity == ValidationSeverity::Error);

                        for d in &diagnostics {
                            self.core.log_audit(
                                "POLICY_VALIDATION",
                                serde_json::json!({
                                    "severity": format!("{:?}", d.severity),
                                    "field_path": d.field_path,
                                    "rule_index": d.rule_index,
                                    "message": d.message,
                                    "suggestion": d.suggestion,
                                }),
                            );
                            if d.severity == ValidationSeverity::Error {
                                error!(
                                    field = %d.field_path,
                                    rule = ?d.rule_index,
                                    suggestion = ?d.suggestion,
                                    "Policy validation error: {}",
                                    d.message
                                );
                            } else {
                                warn!(
                                    field = %d.field_path,
                                    rule = ?d.rule_index,
                                    suggestion = ?d.suggestion,
                                    "Policy validation warning: {}",
                                    d.message
                                );
                            }
                        }

                        if has_errors {
                            error!(
                                "Policy '{}' has validation errors — not loading (fail-closed). \
                                 Fix all [Error] diagnostics above and restart.",
                                p.name
                            );
                        } else {
                            info!(
                                policy = %p.name,
                                warnings = diagnostics.len(),
                                "Loaded policy from {}",
                                path.display()
                            );
                            self.core.set_policy(p);
                        }
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
                    let key = if let Some(id_str) = id.as_str() {
                        Some(id_str.to_string())
                    } else {
                        id.as_i64().map(|n| n.to_string())
                    };
                    if let Some(key) = key {
                        self.pending_decisions.insert(key.clone(), decision.clone());
                        self.pending_methods.insert(key, req.method.clone());
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
        #[cfg(feature = "telemetry")]
        let _span =
            lilith_telemetry::telemetry_span!("mcp_response", lilith_telemetry::SpanKind::Server);

        let mut decision = SecurityDecision::Allow; // Default if unsolicited (notifications)?

        let id_key = if let Some(id_str) = resp.id.as_str() {
            Some(id_str.to_string())
        } else {
            resp.id.as_i64().map(|id_num| id_num.to_string())
        };

        let mut pending_method: Option<String> = None;
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
            pending_method = self.pending_methods.remove(&key);
        }

        // Rug-pull protection: verify tool descriptions against stored pins on tools/list.
        if pending_method.as_deref() == Some(crate::engine_core::constants::methods::TOOLS_LIST) {
            if let Some(result) = &resp.result {
                if let Some(tools_arr) = result.get("tools").and_then(|v| v.as_array()) {
                    let pairs: Vec<(String, String)> = tools_arr
                        .iter()
                        .filter_map(|t| {
                            let name = t.get("name")?.as_str()?.to_string();
                            let desc = t
                                .get("description")
                                .and_then(|d| d.as_str())
                                .unwrap_or("")
                                .to_string();
                            Some((name, desc))
                        })
                        .collect();

                    let violations = self.pin_store.observe(&pairs);
                    if !violations.is_empty() {
                        let names: Vec<&str> =
                            violations.iter().map(|v| v.tool_name.as_str()).collect();
                        let msg = format!(
                            "Tool description rug-pull detected for: {}",
                            names.join(", ")
                        );
                        self.core.log_audit(
                            "RUG_PULL_DETECTED",
                            serde_json::json!({
                                "tools": names,
                                "action": if self.pin_store.mode == crate::config::PinMode::Enforce {
                                    "BLOCK"
                                } else {
                                    "AUDIT"
                                }
                            }),
                        );

                        if self.pin_store.mode == crate::config::PinMode::Enforce {
                            warn!("{}", msg);
                            let _ = self
                                .write_error(
                                    writer,
                                    resp.id.clone(),
                                    crate::engine_core::constants::jsonrpc::ERROR_SECURITY_BLOCK,
                                    &msg,
                                )
                                .await;
                            return Ok(());
                        }
                    }
                }
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
