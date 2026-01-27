//! MCP Middleware implementation.
//!
//! This module implements the main `McpMiddleware` which acts as a proxy
//! between an MCP client (like Claude Desktop) and an upstream MCP server.
//! It enforces security policies on tool calls and resources.

use crate::config::Config;
use crate::constants::{jsonrpc, policy, session, methods};
use crate::core::crypto::CryptoSigner;
use crate::core::models::{Decision, HistoryEntry, PolicyDefinition};
use crate::engine::evaluator::PolicyEvaluator;
use crate::mcp::process::ProcessSupervisor;
use crate::mcp::security::SecurityEngine;
use crate::mcp::transport::{JsonRpcRequest, JsonRpcResponse, StdioTransport};
use crate::utils::audit_logger::{AuditLogger, AuditEntry, AuditEventType};

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, info, warn};

pub struct McpMiddleware {
    transport: StdioTransport,
    upstream: Option<ProcessSupervisor>,
    upstream_stdin: Option<tokio::process::ChildStdin>,
    upstream_stdout: Option<tokio::io::BufReader<tokio::process::ChildStdout>>,
    upstream_cmd: String,
    upstream_args: Vec<String>,
    config: Arc<Config>,
    session_id: String,
    signer: CryptoSigner,
    history: Vec<HistoryEntry>,
    taints: HashSet<String>,
    policy: Option<PolicyDefinition>,
}

impl McpMiddleware {
    pub fn new(upstream_cmd: String, upstream_args: Vec<String>, config: Arc<Config>) -> Self {
        let signer = CryptoSigner::new();
        let session_id = signer.generate_session_id();

        Self {
            transport: StdioTransport::new(),
            upstream: None,
            upstream_stdin: None,
            upstream_stdout: None,
            upstream_cmd,
            upstream_args,
            config,
            session_id,
            signer,
            history: Vec::new(),
            taints: HashSet::new(),
            policy: None,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        // Output session ID in a parseable format for the SDK
        eprintln!("{}{}", session::SESSION_ID_ENV_PREFIX, self.session_id);

        // Emit session start audit log
        AuditLogger::log(AuditEntry {
            timestamp: AuditLogger::now(),
            session_id: self.session_id.clone(),
            event_type: AuditEventType::SessionStart,
            tool: None,
            decision: None,
            details: None,
        });

        info!(
            "Sentinel MCP Middleware started. Session: {}",
            self.session_id
        );

        // Print Sentinel Banner
        eprintln!(
            "Sentinel Security Middleware v{} (Session: {})",
            env!("CARGO_PKG_VERSION"),
            self.session_id
        );

        // Try to load policy from config path if provided
        if let Some(ref path) = self.config.policies_yaml_path {
            match std::fs::read_to_string(path) {
                Ok(content) => match serde_yaml::from_str::<PolicyDefinition>(&content) {
                    Ok(p) => {
                        info!("Loaded policy from {}", path.display());
                        self.policy = Some(p);
                    }
                    Err(e) => error!("Failed to parse policy YAML: {}", e),
                },
                Err(e) => error!("Failed to read policy file: {}", e),
            }
        }

        // Fallback policy if none loaded
        if self.policy.is_none() {
            warn!("No policy loaded. Using default permissive policy (ALLOW ALL).");
            self.policy = Some(PolicyDefinition {
                id: policy::DEFAULT_POLICY_ID.to_string(),
                customer_id: policy::DEFAULT_POLICY_ID.to_string(),
                name: policy::DEFAULT_POLICY_NAME.to_string(),
                version: 1,
                static_rules: HashMap::new(),
                taint_rules: vec![],
                created_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        loop {
            let req_opt = self.transport.read_message().await?;
            if req_opt.is_none() {
                break; // EOF
            }
            let req = req_opt.unwrap();

            match req.method.as_str() {
                methods::INITIALIZE => self.handle_initialize(req).await?,
                methods::TOOLS_LIST => self.handle_tools_list(req).await?,
                methods::TOOLS_CALL => self.handle_tools_call(req).await?,
                _ => self.forward_or_error(req).await?,
            }
        }
        Ok(())
    }

    fn validate_session(&self, params: &Option<Value>) -> Result<(), String> {
        // In "Local" mode, we might be lenient, but the plan requires strict HMAC checks.
        // We look for `_sentinel_session_id` in the params object.
        if let Some(p) = params {
            if let Some(obj) = p.as_object() {
                if let Some(sid) = obj.get(session::SESSION_ID_PARAM) {
                    if let Some(sid_str) = sid.as_str() {
                        if self.signer.validate_session_id(sid_str) {
                            // Additionally check if it matches OUR session_id (replay protection/binding)
                            if sid_str == self.session_id {
                                return Ok(());
                            } else {
                                return Err("Session ID mismatch".to_string());
                            }
                        } else {
                            return Err("Invalid Session ID signature".to_string());
                        }
                    }
                }
            }
        }
        // If missing or invalid structure
        Err("Missing or invalid _sentinel_session_id".to_string())
    }

    async fn handle_initialize(&mut self, req: JsonRpcRequest) -> Result<()> {
        // Initialize is often the first call.
        
        // Audience Binding (Phase 3.1)
        if let Some(expected) = &self.config.expected_audience {
            let token = req.params.as_ref()
                .and_then(|v| v.as_object())
                .and_then(|obj| obj.get("_sentinel_token"))
                .and_then(|v| v.as_str());

            if let Some(token_str) = token {
                if let Err(e) = crate::core::auth::validate_audience_claim(token_str, expected) {
                    warn!("Audience binding failed: {}", e);
                     self.transport.write_error(
                        req.id.unwrap_or(serde_json::Value::Null),
                        jsonrpc::ERROR_AUTH,
                        &format!("Audience Binding Error: {}", e),
                    ).await?;
                    return Ok(()); // Abort initialization
                }
            } else {
                 warn!("Missing required _sentinel_token for audience binding");
                 self.transport.write_error(
                    req.id.unwrap_or(serde_json::Value::Null),
                    jsonrpc::ERROR_AUTH,
                    "Missing required _sentinel_token for audience binding",
                ).await?;
                return Ok(());
            }
        }

        info!(
            "Spawning upstream: {} {:?}",
            self.upstream_cmd, self.upstream_args
        );
        let mut supervisor = ProcessSupervisor::spawn(&self.upstream_cmd, &self.upstream_args)
            .context("Failed to spawn upstream")?;
        info!("Upstream spawned successfully");
        self.upstream_stdin = supervisor.child.stdin.take();
        self.upstream_stdout = supervisor.child.stdout.take().map(BufReader::new);
        
        // Deadlock Fix: Drain stderr to prevent pipe buffer filling
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

        info!("Transacting initialize with upstream...");
        let resp = self.transact_upstream(req).await?;
        info!("Initialize transaction complete");
        self.transport.write_response(resp).await?;
        Ok(())
    }

    async fn handle_tools_list(&mut self, req: JsonRpcRequest) -> Result<()> {
        // Validate Session
        if let Err(e) = self.validate_session(&req.params) {
            warn!("Blocked tools/list: {}", e);
            if let Some(id) = req.id {
                self.transport
                    .write_error(
                        id,
                        jsonrpc::ERROR_AUTH,
                        &format!("Sentinel Auth Error: {}", e),
                    )
                    .await?;
            }
            return Ok(());
        }

        let resp = self.transact_upstream(req).await?;
        self.transport.write_response(resp).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self, req), fields(method = %req.method, id = ?req.id, tool_name, decision, user = %self.config.owner))]
    async fn handle_tools_call(&mut self, mut req: JsonRpcRequest) -> Result<()> {
        // Validate Session
        if let Err(e) = self.validate_session(&req.params) {
            warn!("Blocked tools/call: {}", e);
            if let Some(id) = req.id {
                self.transport
                    .write_error(
                        id,
                        jsonrpc::ERROR_AUTH,
                        &format!("Sentinel Auth Error: {}", e),
                    )
                    .await?;
            }
            return Ok(());
        }

        // Extract needed values first (name, args) to drop immutable borrow of req.params
        let (name, args) = {
            let params = req
                .params
                .as_ref()
                .and_then(|v| v.as_object())
                .context("Invalid params")?;
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .context("Missing tool name")?
                .to_string();
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            (name, args)
        };
        
        // Record tool name in current span
        tracing::Span::current().record("tool_name", &name);

        // Strip _sentinel_session_id before forwarding to tool
        if let Some(p) = req.params.as_mut() {
            if let Some(obj) = p.as_object_mut() {
                obj.remove(session::SESSION_ID_PARAM);
            }
        }

        // Auto-classify for MVP
        let classes = if name.starts_with("read_") || name.starts_with("get_") {
            vec!["READ".to_string()]
        } else if name.starts_with("write_") || name.starts_with("delete_") {
            vec!["WRITE".to_string()]
        } else {
            vec![]
        };

        let policy = self.policy.as_ref().context("Policy not initialized")?;

        // Evaluate
        let decision = PolicyEvaluator::evaluate_with_args(
            policy,
            &name,
            &classes,
            &self.history,
            &self.taints,
            &args,
        )
        .await?;

        match decision {
            Decision::Allowed => {
                AuditLogger::log(AuditEntry {
                    timestamp: AuditLogger::now(),
                    session_id: self.session_id.clone(),
                    event_type: AuditEventType::Decision,
                    tool: Some(name.clone()),
                    decision: Some("ALLOWED".to_string()),
                    details: None,
                });
                self.execute_tool(req, &name, &classes).await
            }
            Decision::AllowedWithSideEffects {
                taints_to_add,
                taints_to_remove,
            } => {
                let details = serde_json::json!({
                    "taints_added": taints_to_add,
                    "taints_removed": taints_to_remove
                });
                AuditLogger::log(AuditEntry {
                    timestamp: AuditLogger::now(),
                    session_id: self.session_id.clone(),
                    event_type: AuditEventType::Decision,
                    tool: Some(name.clone()),
                    decision: Some("ALLOWED_WITH_SIDE_EFFECTS".to_string()),
                    details: Some(details),
                });
                for t in taints_to_add {
                    self.taints.insert(t);
                }
                for t in taints_to_remove {
                    self.taints.remove(&t);
                }
                self.execute_tool(req, &name, &classes).await
            }
            Decision::Denied { reason } => {
                warn!("Blocked tool call {}: {}", name, reason);
                AuditLogger::log(AuditEntry {
                    timestamp: AuditLogger::now(),
                    session_id: self.session_id.clone(),
                    event_type: AuditEventType::Decision,
                    tool: Some(name.clone()),
                    decision: Some("DENIED".to_string()),
                    details: Some(serde_json::json!({"reason": reason})),
                });
                if let Some(id) = req.id {
                    self.transport
                        .write_error(
                            id,
                            jsonrpc::ERROR_SECURITY_BLOCK,
                            &format!("Sentinel Security Block: {}", reason),
                        )
                        .await?;
                }
                Ok(())
            }
        }
    }

    async fn execute_tool(
        &mut self,
        req: JsonRpcRequest,
        name: &str,
        classes: &[String],
    ) -> Result<()> {
        let resp = self.transact_upstream(req).await?;

        // Record history
        self.history.push(HistoryEntry {
            tool: name.to_string(),
            classes: classes.to_vec(),
            timestamp: crate::utils::time::now(),
        });

        // Apply security transformations
        let secured_resp = self.process_secure_response(resp).await?;

        self.transport.write_response(secured_resp).await?;
        Ok(())
    }

    async fn forward_or_error(&mut self, req: JsonRpcRequest) -> Result<()> {
        if self.upstream.is_some() {
            if req.id.is_none() {
                let json = serde_json::to_string(&req)?;
                if let Some(stdin) = &mut self.upstream_stdin {
                    stdin.write_all(json.as_bytes()).await?;
                    stdin.write_all(b"\n").await?;
                    stdin.flush().await?;
                }
            } else {
                let resp = self.transact_upstream(req).await?;
                // Apply security even for forwarded requests (e.g. direct resource reads)
                let secured_resp = self.process_secure_response(resp).await?;
                self.transport.write_response(secured_resp).await?;
            }
        } else if let Some(id) = req.id {
            self.transport
                .write_error(
                    id,
                    jsonrpc::ERROR_METHOD_NOT_FOUND,
                    "Upstream not connected",
                )
                .await?;
        }
        Ok(())
    }

    async fn process_secure_response(&self, mut resp: JsonRpcResponse) -> Result<JsonRpcResponse> {
        if let Some(result) = &mut resp.result {
            // 1. Check 'content' (Tools)
            self.spotlight_content_array(result.get_mut("content"));

            // 2. Check 'contents' (Resources)
            self.spotlight_content_array(result.get_mut("contents"));
        }
        Ok(resp)
    }

    fn spotlight_content_array(&self, value: Option<&mut Value>) {
        if let Some(v) = value {
            if let Some(arr) = v.as_array_mut() {
                for item in arr {
                    if let Some(text) = item.get_mut("text") {
                        if let Some(s) = text.as_str() {
                            // Only spotlight if not already spotlighted?
                            // SecurityEngine::spotlight is idempotent-ish (adds wrapping),
                            // but we shouldn't wrap twice if we can avoid it.
                            // For now, assume single pass.
                            let spotlighted = SecurityEngine::spotlight(s);
                            *text = Value::String(spotlighted);
                        }
                    }
                }
            }
        }
    }

    async fn transact_upstream(&mut self, req: JsonRpcRequest) -> Result<JsonRpcResponse> {
        let json = serde_json::to_string(&req)?;
        let stdin = self
            .upstream_stdin
            .as_mut()
            .context("Upstream stdin not available")?;
        let stdout = self
            .upstream_stdout
            .as_mut()
            .context("Upstream stdout not available")?;

        stdin.write_all(json.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;

        info!("Reading line from upstream stdout...");
        let mut line = String::new();
        stdout
            .read_line(&mut line)
            .await
            .context("Failed to read line from upstream")?;
        info!("Received line from upstream: {}", line.trim());

        // Handle empty line (EOF or crash)?
        if line.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "Upstream returned empty response (process died?)"
            ));
        }

        let resp: JsonRpcResponse =
            serde_json::from_str(&line).context("Failed to parse upstream response")?;
        Ok(resp)
    }
}
