//! MCP Middleware implementation.
//! 
//! This module implements the main `McpMiddleware` which acts as a proxy
//! between an MCP client and an upstream MCP server.
//! 
//! v2 Architecture (Permanent Sentinel):
//! - Decoupled from wire protocol via `ProtocolAdapter`
//! - Centralized security logic in `SecurityCore`
//! - Simplified main loop

use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use anyhow::{Context, Result};
use serde_json::Value;

use crate::config::Config;
use crate::constants::{jsonrpc, session};
use crate::core::crypto::CryptoSigner;
use crate::core::events::{SecurityEvent, SecurityDecision};
use crate::core::security_core::SecurityCore;
use crate::core::session::ActiveSession;
use crate::mcp::process::ProcessSupervisor;
use crate::protocol::types::{JsonRpcRequest, JsonRpcResponse};
use crate::protocol::traits::McpSessionHandler;
use crate::protocol::negotiation::HandshakeManager;
use crate::mcp::transport::StdioTransport;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

pub struct McpMiddleware {
    transport: StdioTransport,
    upstream: Option<ProcessSupervisor>,
    upstream_stdin: Option<tokio::process::ChildStdin>,
    upstream_stdout: Option<tokio::io::BufReader<tokio::process::ChildStdout>>,
    upstream_cmd: String,
    upstream_args: Vec<String>,
    // Core Security Logic
    core: SecurityCore,
    // Active Protocol Session (Gateway)
    session: ActiveSession,
}

impl McpMiddleware {
    pub fn new(upstream_cmd: String, upstream_args: Vec<String>, config: Arc<Config>) -> Self {
        let signer = CryptoSigner::new();
        // Initialize Security Core
        let core = SecurityCore::new(config.clone(), signer);
        
        // Negotiate/Initialize Session based on config
        let session = HandshakeManager::negotiate(&config.mcp_version);

        Self {
            transport: StdioTransport::new(),
            upstream: None,
            upstream_stdin: None,
            upstream_stdout: None,
            upstream_cmd,
            upstream_args,
            core,
            session,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        // Output session ID for SDK interaction
        eprintln!("{}{}", session::SESSION_ID_ENV_PREFIX, self.core.session_id);

        info!("Sentinel Middleware v2 started. Session: {}", self.core.session_id);
        eprintln!(
            "Sentinel Security Middleware v{} (Session: {})",
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
             warn!("No policy loaded. Using default permissive behavior.");
        }

        loop {
            let req_opt = self.transport.read_message().await?;
            if req_opt.is_none() {
                break; // EOF
            }
            let mut req = req_opt.unwrap();

            // 1. Parse Protocol
            let event = self.session.parse_request(&req);

            // 2. Evaluate Security
            let decision = self.core.evaluate(event.clone()).await;

            // 3. Act on Decision
            match decision {
                SecurityDecision::Deny { error_code, reason } => {
                    warn!("Blocked request: {}", reason);
                    if let Some(id) = req.id {
                        self.transport.write_error(id, error_code, &reason).await?;
                    }
                },
                SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {
                    // Handle Infrastructure Side Effects (Spawning & Negotiation)
                    if let SecurityEvent::Handshake { protocol_version, .. } = &event {
                        // 1. Protocol Negotiation (Gateway Switch)
                        if protocol_version != self.session.version() {
                            info!("Negotiating protocol: Client requested {}, upgrading session.", protocol_version);
                            self.session = HandshakeManager::negotiate(&protocol_version);
                        }

                        // 2. Spawn Upstream
                        if self.upstream.is_none() {
                            if let Err(e) = self.spawn_upstream() {
                                error!("Failed to spawn upstream: {}", e);
                                if let Some(id) = req.id {
                                    self.transport.write_error(
                                        id, 
                                        jsonrpc::ERROR_INTERNAL, 
                                        "Failed to start upstream process"
                                    ).await?;
                                }
                                continue;
                            }
                        }
                    }

                    // Forward to Upstream
                    if self.upstream.is_some() {
                        // Sanitize request (remove internal session tokens)
                        self.session.sanitize_for_upstream(&mut req);
                        
                        match self.transact_upstream(req).await {
                            Ok(resp) => {
                                // Apply Output Transforms (Spotlighting)
                                let secured_resp = self.session.apply_decision(&decision, resp);
                                self.transport.write_response(secured_resp).await?;
                            },
                            Err(e) => {
                                error!("Upstream transaction failed: {}", e);
                                break;
                            }
                        }
                    } else {
                         if let Some(id) = req.id {
                             self.transport.write_error(
                                 id,
                                 jsonrpc::ERROR_METHOD_NOT_FOUND,
                                 "Upstream not connected (Handshake required)"
                             ).await?;
                         }
                    }
                }
            }
        }
        Ok(())
    }

    fn spawn_upstream(&mut self) -> Result<()> {
        info!("Spawning upstream: {} {:?}", self.upstream_cmd, self.upstream_args);
        let mut supervisor = ProcessSupervisor::spawn(&self.upstream_cmd, &self.upstream_args)
            .context("Failed to spawn upstream")?;
        
        self.upstream_stdin = supervisor.child.stdin.take();
        self.upstream_stdout = supervisor.child.stdout.take().map(BufReader::new);
        
        // Drain stderr
        if let Some(stderr) = supervisor.child.stderr.take() {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr);
                let mut line = String::new();
                while let Ok(bytes) = reader.read_line(&mut line).await {
                    if bytes == 0 { break; }
                    debug!("[Upstream Stderr] {}", line.trim());
                    line.clear();
                }
            });
        }
        
        self.upstream = Some(supervisor);
        Ok(())
    }

    async fn transact_upstream(&mut self, req: JsonRpcRequest) -> Result<JsonRpcResponse> {
        let json = serde_json::to_string(&req)?;
        let stdin = self.upstream_stdin.as_mut().context("Upstream stdin missing")?;
        let stdout = self.upstream_stdout.as_mut().context("Upstream stdout missing")?;

        debug!("Writing to upstream: {}", json);
        stdin.write_all(json.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        debug!("Flushed to upstream");

        if req.id.is_none() {
             return Ok(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: None,
                id: Value::Null,
            });
        }

        // Loop to filter out upstream noise
        let mut attempts = 0;
        let max_attempts = 1000; 

        loop {
            if attempts >= max_attempts {
                 return Err(anyhow::anyhow!("Upstream unresponsive or flooding noise."));
            }
            attempts += 1;
            debug!("Waiting for upstream response (attempt {})", attempts);

            let mut line = String::new();
            match timeout(UPSTREAM_TIMEOUT, stdout.read_line(&mut line)).await {
                Ok(Ok(_)) => {}, // Success
                Ok(Err(e)) => return Err(anyhow::anyhow!("Failed to read from upstream: {}", e)),
                Err(_) => return Err(anyhow::anyhow!("Upstream unresponsive (timeout)")),
            }
            
            if line.trim().is_empty() {
                 if line.is_empty() {
                      return Err(anyhow::anyhow!("Upstream execution returned EOF (process died?)"));
                 }
                 continue; 
            }

            if !line.trim().starts_with('{') {
                debug!("[Upstream Noise] {}", line.trim());
                continue;
            }

            match serde_json::from_str::<JsonRpcResponse>(&line) {
                Ok(resp) => {
                    debug!("Parsed upstream response (id: {:?})", resp.id);
                    
                    // Verify ID matches request (hardening against stale responses/noise)
                    if let Some(req_id) = &req.id {
                        if &resp.id != req_id {
                            warn!("Ignoring mismatched response ID: {:?} (expected {:?})", resp.id, req_id);
                            continue;
                        }
                    } else if !resp.id.is_null() {
                         // If request has no ID (shouldn't be here due to early return), match Null.
                         // But we returned early if req.id.is_none().
                         // So req.id is Some.
                    }

                    return Ok(resp)
                },
                Err(e) => {
                    warn!("[Upstream Malformed JSON] {} - Error: {}", line.trim(), e);
                    continue;
                }
            }
        }
    }
}
