//! MCP Middleware implementation (Actor Model).
//! 
//! v3 Architecture (Async Actors):
//! - `DownstreamReader`: Reads client JSON-RPC requests.
//! - `UpstreamReader`: Reads tool JSON-RPC responses.
//! - `McpMiddleware` (Main Loop): Coordinator acting as the central actor.
//!   - Maintains `pending_decisions` map for request/response correlation.
//!   - Routes messages between Upstream and Downstream.
//!   - Enforces Security Policies.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use anyhow::{Context, Result};
use serde_json::Value;

use crate::config::Config;
use crate::core::constants::{jsonrpc, session};
use crate::core::crypto::CryptoSigner;
use crate::core::events::{SecurityEvent, SecurityDecision};
use crate::core::security_core::SecurityCore;
use crate::core::session::ActiveSession;
use crate::mcp::process::ProcessSupervisor;
use crate::core::models::{JsonRpcRequest, JsonRpcResponse, JsonRpcError};
use crate::core::traits::McpSessionHandler;
use crate::protocol::negotiation::HandshakeManager;
use crate::mcp::pipeline::{self, DownstreamEvent, UpstreamEvent};

pub struct McpMiddleware {
    upstream_cmd: String,
    upstream_args: Vec<String>,
    // Core Security Logic
    core: SecurityCore,
    // Active Protocol Session (Gateway)
    session: ActiveSession,
    
    // Actor State
    upstream_stdin: Option<tokio::process::ChildStdin>,
    pending_decisions: HashMap<String, SecurityDecision>, // Map Request ID (String) -> Decision
    
    // Upstream Control
    upstream_supervisor: Option<ProcessSupervisor>,
}

impl McpMiddleware {
    pub fn new(upstream_cmd: String, upstream_args: Vec<String>, config: Arc<Config>) -> Result<Self> {
        let signer = CryptoSigner::try_new().map_err(|e| anyhow::anyhow!("Crypto init failed: {}", e))?;
        let core = SecurityCore::new(config.clone(), signer).map_err(|e| anyhow::anyhow!("Security Core init failed: {}", e))?;
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
        // Output session ID for SDK interaction (REQUIRED)
        eprintln!("{}{}", session::SESSION_ID_ENV_PREFIX, self.core.session_id);

        info!("Sentinel Middleware v3 (Actor Model) started. Session: {}", self.core.session_id);
        eprintln!("Sentinel Middleware v{} (Session: {})", env!("CARGO_PKG_VERSION"), self.core.session_id);

        // Load Policies
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
             warn!("No policy loaded. Using default permissive behavior.");
        }

        // Setup Channels
        let (tx_downstream_events, mut rx_downstream_events) = mpsc::channel(32);
        let (tx_upstream_events, mut rx_upstream_events) = mpsc::channel(32);

        // Spawn Downstream Reader (Stdin)
        pipeline::spawn_downstream_reader(tokio::io::stdin(), tx_downstream_events);

        // We use tokio::io::stdout() for writing to client directly in the main loop for now (Writer Task could be separate but simple write is okay)
        let mut downstream_writer = tokio::io::stdout();

        loop {
            tokio::select! {
                // --- Handle Downstream (Client) Events ---
                event = rx_downstream_events.recv() => {
                    match event {
                        Some(DownstreamEvent::Request(mut req)) => {
                            self.handle_client_request(&mut req, &mut downstream_writer, &tx_upstream_events).await?;
                        }
                        Some(DownstreamEvent::Disconnect) => {
                            info!("Client disconnected. Shutting down.");
                            break;
                        }
                        Some(DownstreamEvent::Error(e)) => {
                            warn!("Downstream transport error: {}", e);
                            // Optionally send error back if possible?
                        }
                        None => break, // Channel closed
                    }
                }

                // --- Handle Upstream (tool) Events ---
                event = rx_upstream_events.recv() => {
                    match event {
                        Some(UpstreamEvent::Response(resp)) => {
                            self.handle_upstream_response(resp, &mut downstream_writer).await?;
                        }
                        Some(UpstreamEvent::Log(msg)) => {
                            debug!("[Upstream Log] {}", msg);
                        }
                        Some(UpstreamEvent::Terminated) => {
                            warn!("Upstream process terminated unexpectedly.");
                            self.upstream_stdin = None;
                            self.upstream_supervisor = None;
                            // We don't exit, we might restart or just report error on next request.
                        }
                        None => {
                            // Upstream channel closed (shouldn't happen unless we drop sender)
                        }
                    }
                }
                
                // --- Signals ---
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
        tx_upstream_events: &mpsc::Sender<UpstreamEvent>
    ) -> Result<()> {
        // 1. Parse Protocol (Session Token extraction, etc)
        let security_event = self.session.parse_request(req);

        // 2. Evaluate Security
        let decision = self.core.evaluate(security_event.clone()).await;

        match decision {
            SecurityDecision::Deny { error_code, reason } => {
                warn!("Blocked request: {}", reason);
                if let Some(id) = &req.id {
                    self.write_error(writer, id.clone(), error_code, &reason).await?;
                }
            }
            SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {
                // Handle Side Effects (Infra)
                if let SecurityEvent::Handshake { protocol_version, .. } = &security_event {
                    // Negotiation
                    if protocol_version != self.session.version() {
                         info!("Negotiating protocol: Client requested {}, upgrading session.", protocol_version);
                         self.session = HandshakeManager::negotiate(protocol_version);
                    }
                    
                    // Spawn Upstream if needed
                    if self.upstream_stdin.is_none() {
                        if let Err(e) = self.spawn_upstream(tx_upstream_events.clone()) {
                             error!("Failed to spawn upstream: {}", e);
                             if let Some(id) = &req.id {
                                 self.write_error(writer, id.clone(), jsonrpc::ERROR_INTERNAL, "Failed to start upstream process").await?;
                             }
                             return Ok(());
                        }
                    }
                }

                // Track Decision for Response (if request has ID)
                if let Some(id) = &req.id {
                    // We map the ID as string.
                    if let Some(id_str) = id.as_str() {
                        self.pending_decisions.insert(id_str.to_string(), decision.clone());
                    } else if let Some(id_num) = id.as_i64() {
                         self.pending_decisions.insert(id_num.to_string(), decision.clone());
                    }
                }

                // Forward to Upstream
                if self.upstream_stdin.is_some() {
                    self.session.sanitize_for_upstream(req);
                    // Blessing the request as clean because Policy Allowed it.
                    let clean_req = crate::core::taint::Clean::new_unchecked(req.clone());
                    self.write_upstream(clean_req).await?;
                } else if let Some(id) = &req.id {
                    self.write_error(writer, id.clone(), jsonrpc::ERROR_METHOD_NOT_FOUND, "Upstream not connected").await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_upstream_response(
        &mut self,
        resp: JsonRpcResponse,
        writer: &mut tokio::io::Stdout
    ) -> Result<()> {
        // Correlate with Request
        let mut decision = SecurityDecision::Allow; // Default if unsolicited (notifications)?
        
        let id_key = if let Some(id_str) = resp.id.as_str() {
            Some(id_str.to_string())
        } else { resp.id.as_i64().map(|id_num| id_num.to_string()) };

        if let Some(key) = id_key {
            if let Some(d) = self.pending_decisions.remove(&key) {
                decision = d;
            } else if !resp.id.is_null() {
                warn!("Received upstream response with unknown ID: {:?}. Dropping.", resp.id);
                return Ok(());
            }
        }

        // Apply Transforms (Spotlighting)
        let secured_resp = self.session.apply_decision(&decision, resp);
        
        // Write to Downstream
        let json = serde_json::to_string(&secured_resp)?;
        debug!("Writing downstream: {}", json);
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        Ok(())
    }

    fn spawn_upstream(&mut self, tx_upstream: mpsc::Sender<UpstreamEvent>) -> Result<()> {
        info!("Spawning upstream: {} {:?}", self.upstream_cmd, self.upstream_args);
        
        let mut supervisor = ProcessSupervisor::spawn(&self.upstream_cmd, &self.upstream_args)
            .context("Failed to spawn upstream")?;
        
        // Capture Stdin
        self.upstream_stdin = supervisor.child.stdin.take();
        
        // Capture and spawn reader for Stdout
        if let Some(stdout) = supervisor.child.stdout.take() {
            pipeline::spawn_upstream_reader(stdout, tx_upstream.clone());
        }
        
        // Capture and spawn drain for Stderr
        if let Some(stderr) = supervisor.child.stderr.take() {
            pipeline::spawn_upstream_stderr_drain(stderr, tx_upstream.clone());
        }

        self.upstream_supervisor = Some(supervisor);
        Ok(())
    }

    async fn write_upstream(&mut self, req: crate::core::taint::Clean<JsonRpcRequest>) -> Result<()> {
        if let Some(stdin) = self.upstream_stdin.as_mut() {
            // We use into_inner() because we are at the Sink boundary.
            let json = serde_json::to_string(&req.into_inner())?;
            debug!("Writing upstream: {}", json);
            stdin.write_all(json.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await?;
        }
        Ok(())
    }

    async fn write_error(&self, writer: &mut tokio::io::Stdout, id: Value, code: i32, message: &str) -> Result<()> {
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
        let json = serde_json::to_string(&response)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        Ok(())
    }
}
