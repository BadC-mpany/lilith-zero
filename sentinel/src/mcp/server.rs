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
use tracing::{debug, error, info, warn};
use anyhow::{Context, Result};
use serde_json::Value;

use crate::config::Config;
use crate::constants::{jsonrpc, session};
use crate::core::crypto::CryptoSigner;
use crate::core::events::{SecurityEvent, SecurityDecision};
use crate::core::security_core::SecurityCore;
use crate::mcp::process::ProcessSupervisor;
use crate::mcp::transport::{JsonRpcRequest, JsonRpcResponse, StdioTransport};
use crate::mcp::adapter::ProtocolAdapter;

pub struct McpMiddleware {
    transport: StdioTransport,
    upstream: Option<ProcessSupervisor>,
    upstream_stdin: Option<tokio::process::ChildStdin>,
    upstream_stdout: Option<tokio::io::BufReader<tokio::process::ChildStdout>>,
    upstream_cmd: String,
    upstream_args: Vec<String>,
    // Core Security Logic
    core: SecurityCore,
    // Protocol Adapter (Versioned)
    adapter: Box<dyn ProtocolAdapter>,
}

impl McpMiddleware {
    pub fn new(upstream_cmd: String, upstream_args: Vec<String>, config: Arc<Config>) -> Self {
        let signer = CryptoSigner::new();
        // Initialize Security Core
        let core = SecurityCore::new(config.clone(), signer);
        
        // Select Adapter based on config
        let adapter: Box<dyn ProtocolAdapter> = match config.mcp_version.as_str() {
            "2025-06-18" | "2025" => {
                info!("Initializing with MCP 2025 Adapter");
                Box::new(crate::mcp::adapters::mcp_2025::Mcp2025Adapter)
            }
            _ => {
                info!("Initializing with MCP 2024 Adapter");
                Box::new(crate::mcp::adapters::mcp_2024::Mcp2024Adapter)
            }
        };

        Self {
            transport: StdioTransport::new(),
            upstream: None,
            upstream_stdin: None,
            upstream_stdout: None,
            upstream_cmd,
            upstream_args,
            core,
            adapter,
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

        // Load policy (done in main.rs -> passed in config -> core should load it?)
        // Actually, main.rs parses config. Policy loading logic was in run().
        // We need to move that to Core or keep it here and pass to Core.
        // Let's reload it here or assume config has path and we load it.
        // The previous run() loaded it. Let's do it here and set on core.
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
             // If implicit default policy needed, Core handles it or we set it here.
             // We'll leave it as None in Core (Core assumes Allow if None or handles it).
             warn!("No policy loaded. Using default permissive behavior.");
        }

        loop {
            let req_opt = self.transport.read_message().await?;
            if req_opt.is_none() {
                break; // EOF
            }
            let mut req = req_opt.unwrap();

            // 1. Parse Protocol
            let event = self.adapter.parse_request(&req);

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
                        // 1. Protocol Negotiation (Auto-swap adapter if version differs)
                        if protocol_version != self.adapter.version() {
                            info!("Negotiating protocol: Client requested {}, swapping adapter.", protocol_version);
                            match protocol_version.as_str() {
                                "2025-06-18" | "2025" => {
                                    self.adapter = Box::new(crate::mcp::adapters::mcp_2025::Mcp2025Adapter);
                                },
                                _ => {
                                    self.adapter = Box::new(crate::mcp::adapters::mcp_2024::Mcp2024Adapter);
                                }
                            }
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
                        self.adapter.sanitize_for_upstream(&mut req);
                        
                        match self.transact_upstream(req).await {
                            Ok(resp) => {
                                // Apply Output Transforms (Spotlighting)
                                let secured_resp = self.adapter.apply_decision(&decision, resp);
                                self.transport.write_response(secured_resp).await?;
                            },
                            Err(e) => {
                                error!("Upstream transaction failed: {}", e);
                                // Client might be waiting, send error?
                                // If req had ID, answer.
                                // But transact_upstream failing usually means process died.
                                break;
                            }
                        }
                    } else {
                         // Should typically not happen if Handshake handled correctly, 
                         // unless notification came before handshake?
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

        stdin.write_all(json.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;

        // If notification, we might not get a response? 
        // Logic: specific JSON-RPC methods imply response or not.
        // Sentinel currently treats everything as Request-Response in transact_upstream?
        // Wait, transport definition: `id: Option<Value>`. If None, it's notification.
        // If it's a notification, does upstream reply? 
        // MCP spec: Notifications do NOT expect a response.
        // So blocking on `read_line` for a notification will DEADLOCK if upstream doesn't send anything back promptly.
        
        if req.id.is_none() {
            // It's a notification. Just return a dummy response or handle async?
            // Current sentinel architecture mostly did request/response.
            // But notifications (like `notifications/initialized`) are one-way.
            // We should NOT read from stdout for notifications.
             return Ok(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: None,
                id: Value::Null,
            });
        }

        let mut line = String::new();
        stdout.read_line(&mut line).await.context("Failed to read from upstream")?;
        
        if line.trim().is_empty() {
             return Err(anyhow::anyhow!("Upstream execution returned empty (process died?)"));
        }

        let resp: JsonRpcResponse = serde_json::from_str(&line).context("Failed to parse upstream response")?;
        Ok(resp)
    }
}
