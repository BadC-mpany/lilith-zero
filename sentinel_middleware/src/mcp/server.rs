use crate::mcp::transport::{StdioTransport, JsonRpcRequest, JsonRpcResponse};
use crate::mcp::process::ProcessSupervisor;
use crate::mcp::security::SecurityEngine;
use crate::config::Config;
use crate::core::models::{PolicyDefinition, Decision, HistoryEntry};
use crate::engine::evaluator::PolicyEvaluator;

use std::sync::Arc;
use std::collections::{HashSet, HashMap};
use serde_json::Value;
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub struct McpMiddleware {
    transport: StdioTransport,
    upstream: Option<ProcessSupervisor>,
    upstream_stdin: Option<tokio::process::ChildStdin>,
    upstream_stdout: Option<tokio::io::BufReader<tokio::process::ChildStdout>>,
    upstream_cmd: String,
    upstream_args: Vec<String>,
    config: Arc<Config>,
    session_id: String,
    history: Vec<HistoryEntry>,
    taints: HashSet<String>,
    policy: Option<PolicyDefinition>,
}

impl McpMiddleware {
    pub fn new(upstream_cmd: String, upstream_args: Vec<String>, config: Arc<Config>) -> Self {
        Self {
            transport: StdioTransport::new(),
            upstream: None,
            upstream_stdin: None,
            upstream_stdout: None,
            upstream_cmd,
            upstream_args,
            config,
            session_id: uuid::Uuid::new_v4().to_string(),
            history: Vec::new(),
            taints: HashSet::new(),
            policy: None,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Sentinel MCP Middleware started. Session: {}", self.session_id);

        // Try to load policy from config path if provided
        if let Some(ref path) = self.config.policies_yaml_path {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    match serde_yaml::from_str::<PolicyDefinition>(&content) {
                        Ok(p) => {
                            info!("Loaded policy from {}", path.display());
                            self.policy = Some(p);
                        }
                        Err(e) => error!("Failed to parse policy YAML: {}", e),
                    }
                }
                Err(e) => error!("Failed to read policy file: {}", e),
            }
        }

        // Fallback policy if none loaded
        if self.policy.is_none() {
            warn!("No policy loaded. Using default permissive policy (ALLOW ALL).");
            self.policy = Some(PolicyDefinition {
                id: "default".to_string(),
                customer_id: "default".to_string(),
                name: "Permissive Default".to_string(),
                version: 1,
                static_rules: HashMap::new(), // Default is ALLOW if not DENY specifically?
                // Actually engine/evaluator.rs:49 defaults to "DENY" if not in static_rules.
                // Let's make it permissive for MVP.
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
                "initialize" => self.handle_initialize(req).await?,
                "tools/list" => self.handle_tools_list(req).await?,
                "tools/call" => self.handle_tools_call(req).await?,
                _ => self.forward_or_error(req).await?,
            }
        }
        Ok(())
    }

    async fn handle_initialize(&mut self, req: JsonRpcRequest) -> Result<()> {
        let mut supervisor = ProcessSupervisor::spawn(&self.upstream_cmd, &self.upstream_args)?;
        self.upstream_stdin = supervisor.child.stdin.take();
        self.upstream_stdout = supervisor.child.stdout.take().map(BufReader::new);
        self.upstream = Some(supervisor);

        let resp = self.transact_upstream(req).await?;
        self.transport.write_response(resp).await?;
        Ok(())
    }

    async fn handle_tools_list(&mut self, req: JsonRpcRequest) -> Result<()> {
        let resp = self.transact_upstream(req).await?;
        self.transport.write_response(resp).await?;
        Ok(())
    }

    async fn handle_tools_call(&mut self, req: JsonRpcRequest) -> Result<()> {
        let params = req.params.as_ref().and_then(|v| v.as_object()).context("Invalid params")?;
        let name = params.get("name").and_then(|v| v.as_str()).context("Missing tool name")?.to_string();
        let args = params.get("arguments").cloned().unwrap_or(Value::Null);

        // Get tool classes (mocked for now, or use SupabaseToolRegistry if needed)
        // For simplicity in standalone mode, we assume empty or based on tool name prefixes.
        let classes = if name.starts_with("read_") || name.starts_with("get_") {
            vec!["READ".to_string()]
        } else if name.starts_with("write_") || name.starts_with("delete_") {
            vec!["WRITE".to_string()]
        } else {
            vec![]
        };

        let policy = self.policy.as_ref().unwrap();
        
        // Evaluate
        let decision = PolicyEvaluator::evaluate_with_args(
            policy,
            &name,
            &classes,
            &self.history,
            &self.taints,
            &args
        ).await?;

        match decision {
            Decision::Allowed => {
                self.execute_tool(req, &name, &classes).await
            }
            Decision::AllowedWithSideEffects { taints_to_add, taints_to_remove } => {
                for t in taints_to_add { self.taints.insert(t); }
                for t in taints_to_remove { self.taints.remove(&t); }
                self.execute_tool(req, &name, &classes).await
            }
            Decision::Denied { reason } => {
                warn!("Blocked tool call {}: {}", name, reason);
                if let Some(id) = req.id {
                    self.transport.write_error(id, -32000, &format!("Sentinel Security Block: {}", reason)).await?;
                }
                Ok(())
            }
        }
    }

    async fn execute_tool(&mut self, req: JsonRpcRequest, name: &str, classes: &[String]) -> Result<()> {
        let mut resp = self.transact_upstream(req).await?;
        
        // Record history
        self.history.push(HistoryEntry {
            tool: name.to_string(),
            classes: classes.to_vec(),
            timestamp: crate::utils::time::now(),
        });

        // Spotlight Result
        if let Some(result) = &mut resp.result {
             if let Some(content) = result.get_mut("content") {
                 if let Some(arr) = content.as_array_mut() {
                     for item in arr {
                         if let Some(text) = item.get_mut("text") {
                             if let Some(s) = text.as_str() {
                                 let spotlighted = SecurityEngine::spotlight(s);
                                 *text = Value::String(spotlighted);
                             }
                         }
                     }
                 }
             }
        }

        self.transport.write_response(resp).await?;
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
                self.transport.write_response(resp).await?;
            }
        } else if let Some(id) = req.id {
            self.transport.write_error(id, -32601, "Upstream not connected").await?;
        }
        Ok(())
    }

    async fn transact_upstream(&mut self, req: JsonRpcRequest) -> Result<JsonRpcResponse> {
        let json = serde_json::to_string(&req)?;
        let stdin = self.upstream_stdin.as_mut().context("Upstream stdin not available")?;
        let stdout = self.upstream_stdout.as_mut().context("Upstream stdout not available")?;

        stdin.write_all(json.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;

        let mut line = String::new();
        stdout.read_line(&mut line).await?;
        
        let resp: JsonRpcResponse = serde_json::from_str(&line).context("Failed to parse upstream response")?;
        Ok(resp)
    }
}
