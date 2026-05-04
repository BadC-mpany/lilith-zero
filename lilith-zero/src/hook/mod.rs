// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

/// GitHub Copilot CLI / cloud agent hook adapter.
pub mod copilot;
/// OpenClaw agent hook adapter (forward-looking; based on openclaw/openclaw#60943).
pub mod openclaw;
/// Shared session identity utilities (used by copilot, vscode, and openclaw adapters).
pub mod session;
/// VS Code Copilot sidebar agent hook adapter.
pub mod vscode;

use crate::config::Config;
use crate::engine_core::events::{SecurityDecision, SecurityEvent};
use crate::engine_core::persistence::PersistenceLayer;
use crate::engine_core::security_core::SecurityCore;
use crate::engine_core::taint::Tainted;
use crate::engine_core::types::TaintedString;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

/// Claude Code Hook Input Schema
#[derive(Debug, Deserialize, Serialize)]
pub struct HookInput {
    /// Unique identifier for the Claude session.
    pub session_id: String,
    /// Name of the hook event (e.g. "PreToolUse").
    pub hook_event_name: String,
    /// Name of the tool being executed.
    pub tool_name: Option<String>,
    /// Arguments passed to the tool.
    pub tool_input: Option<serde_json::Value>,
    /// Output returned by the tool (PostToolUse only).
    pub tool_output: Option<serde_json::Value>,
    /// Per-invocation unique ID used for replay nonce protection.
    /// If absent, a timestamp-based value is used so replay nonce
    /// does not block legitimate sequential hook calls.
    #[serde(default)]
    pub request_id: Option<String>,
}

/// Handler for Claude Code hooks, mapping JSON events to security core evaluations.
pub struct HookHandler {
    core: SecurityCore,
    persistence: PersistenceLayer,
}

impl HookHandler {
    /// Create a new HookHandler, loading the policy from disk via `config.policies_yaml_path`.
    ///
    /// Used by hook mode (each invocation is a separate process). For the webhook
    /// server — where the process is long-lived — prefer [`with_policy`] to avoid
    /// a blocking disk read on every request.
    pub fn new(config: Arc<Config>, audit_logs: Option<std::path::PathBuf>) -> Result<Self> {
        let signer = crate::engine_core::crypto::CryptoSigner::try_new()
            .map_err(|e| anyhow::anyhow!("Crypto init failed: {}", e))?;
        let mut core = SecurityCore::new(config.clone(), signer, audit_logs)
            .map_err(|e| anyhow::anyhow!("Security Core init failed: {}", e))?;
        core.validate_session_tokens = false;

        if let Some(path) = &config.policies_yaml_path {
            tracing::info!("Loading hook policy from {:?}", path);
            if path.extension().is_some_and(|ext| ext == "cedar") {
                let content = std::fs::read_to_string(path).map_err(|e| {
                    anyhow::anyhow!("Failed to read Cedar policy file {:?}: {}", path, e)
                })?;
                let policy_set = cedar_policy::PolicySet::from_str(&content)
                    .map_err(|e| anyhow::anyhow!("Failed to parse Cedar policy: {}", e))?;
                core.set_cedar_policy(policy_set);
            } else {
                let content = std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("Failed to read policy file {:?}: {}", path, e))?;
                let policy: crate::engine_core::models::PolicyDefinition =
                    serde_yaml_ng::from_str(&content)
                        .map_err(|e| anyhow::anyhow!("Failed to parse policy YAML: {}", e))?;
                core.set_policy(policy);
            }
        }
        let persistence = PersistenceLayer::default_local();

        Ok(Self { core, persistence })
    }

    /// Create a HookHandler using a pre-parsed policy, bypassing the disk read.
    ///
    /// Used by the webhook server to avoid blocking I/O on every request. The
    /// policy is parsed once at startup and shared via `Arc`.
    pub fn with_policy(
        config: Arc<Config>,
        audit_logs: Option<std::path::PathBuf>,
        policy: Option<Arc<crate::engine_core::models::PolicyDefinition>>,
        cedar_policy: Option<Arc<cedar_policy::PolicySet>>,
    ) -> Result<Self> {
        let signer = crate::engine_core::crypto::CryptoSigner::try_new()
            .map_err(|e| anyhow::anyhow!("Crypto init failed: {}", e))?;
        let mut core = SecurityCore::new(config, signer, audit_logs)
            .map_err(|e| anyhow::anyhow!("Security Core init failed: {}", e))?;
        core.validate_session_tokens = false;

        if let Some(p) = policy {
            core.set_policy((*p).clone());
        }
        if let Some(cp) = cedar_policy {
            core.set_cedar_policy((*cp).clone());
        }
        let persistence = PersistenceLayer::default_local();

        Ok(Self { core, persistence })
    }

    /// Import session state from a [`crate::engine_core::security_core::SessionState`] object.
    pub fn import_state(&mut self, state: crate::engine_core::security_core::SessionState) {
        self.core.import_state(state);
    }

    /// Export the current session state.
    pub fn export_state(&self) -> crate::engine_core::security_core::SessionState {
        self.core.export_state()
    }

    /// Handle a hook input, returning the appropriate process exit code.
    pub async fn handle(&mut self, input: HookInput) -> Result<i32> {
        // Sanitize the session ID before use: it may originate from an untrusted
        // JSON payload (Claude Code hook input, Copilot Studio conversationId).
        // Using the raw value would allow control characters or path separators
        // to reach the audit log and the session file path.
        let session_id = crate::engine_core::persistence::PersistenceLayer::sanitize_session_id(
            &input.session_id,
        );

        // A. Acquire cross-process lock on the session file.
        //    All subsequent reads and writes go through the lock's file handle
        //    so that Windows LockFileEx byte-range locking is respected.
        let mut lock = self.persistence.lock(&session_id)?;

        // B. Load session state through the locked handle.
        let state = lock.load()?;
        let is_new_session = state.is_none();

        if let Some(state) = state {
            self.core.import_state(state);
        }
        self.core.session_id = session_id.clone();

        // C. Silent Handshake (only on first call of session)
        if is_new_session {
            self.perform_silent_handshake().await?;
        }

        // D. Decide exit code based on event
        let exit_code = match input.hook_event_name.as_str() {
            "PreToolUse" => self.handle_pre_tool(&input).await?,
            "PostToolUse" => self.handle_post_tool(&input).await?,
            _ => {
                tracing::warn!("Unknown hook event: {}", input.hook_event_name);
                0 // Unknown events are allowed by default
            }
        };

        // E. Save session state through the locked handle.
        lock.save(&self.core.export_state())?;

        Ok(exit_code)
    }

    async fn perform_silent_handshake(&mut self) -> Result<()> {
        let event = SecurityEvent::Handshake {
            protocol_version: "hook-v1".to_string(), // Synthetic version for hooks
            client_info: serde_json::json!({"client": "claude-code-hook"}),
            audience_token: None,
            capabilities: serde_json::Value::Null,
        };

        // Handshake validation logic (Policy loading, Auth checks)
        let _ = self.core.evaluate(event).await;
        Ok(())
    }

    async fn handle_pre_tool(&mut self, input: &HookInput) -> Result<i32> {
        let tool_name = input.tool_name.as_deref().unwrap_or("unknown");
        let tool_args = input.tool_input.clone().unwrap_or(serde_json::Value::Null);

        // Unique per-invocation ID for replay nonce tracking.  Prefer the adapter-supplied
        // tool_use_id (e.g. OpenClaw's `toolUseId`); fall back to current nanosecond timestamp
        // so that replay protection never blocks legitimate sequential hook calls.
        let req_id = input
            .request_id
            .clone()
            .unwrap_or_else(|| crate::utils::time::now_ms().to_string());

        let event = SecurityEvent::ToolRequest {
            request_id: serde_json::Value::String(req_id),
            tool_name: TaintedString::new(tool_name.to_string()),
            arguments: Tainted::new(tool_args.clone(), vec![]),
            session_token: Some(input.session_id.clone()),
        };

        let decision = self.core.evaluate(event).await;

        if self.core.config.lean_logs {
            let args_summary = if tool_args.is_null() {
                "{}".to_string()
            } else {
                serde_json::to_string(&tool_args).unwrap_or_else(|_| "{}".to_string())
            };
            let taints = self.core.get_taints();
            let taints_str = if taints.is_empty() { "CLEAN".to_string() } else { format!("{:?}", taints) };
            eprintln!(
                "lilith >> tool call: {}({}) [Session: {}] [Taints: {}]",
                tool_name,
                args_summary,
                self.core.session_id,
                taints_str
            );
            
            match &decision {
                SecurityDecision::Allow => {
                    println!("lilith >> decision: ALLOW");
                }
                SecurityDecision::AllowWithTransforms { taints_to_add, .. } => {
                    println!("lilith >> decision: ALLOW");
                    if !taints_to_add.is_empty() {
                        println!("lilith >> action: ADD_TAINT {:?}", taints_to_add);
                    }
                }
                SecurityDecision::Deny { reason, .. } => {
                    println!("lilith >> decision: DENY");
                    println!("lilith >> reason: {}", reason);
                }
            }
        }

        match decision {
            SecurityDecision::Deny { reason, .. } => {
                eprintln!("Blocked action: {}", reason);
                Ok(2) // Claude Code "Block" exit code
            }
            SecurityDecision::AllowWithTransforms {
                taints_to_add: _, ..
            } => {
                // If the evaluator adds taints during REQUEST (e.g. static rule), apply them now.
                // Normally evaluate() updates the internal core state too, but let's be explicit.
                Ok(0)
            }
            _ => Ok(0),
        }
    }

    async fn handle_post_tool(&mut self, input: &HookInput) -> Result<i32> {
        let tool_name = input
            .tool_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let tool_result = input.tool_output.clone().unwrap_or(serde_json::Value::Null);

        let event = SecurityEvent::ToolResponse {
            tool_name: tool_name.clone(),
            result: tool_result,
            session_token: Some(input.session_id.clone()),
        };

        // Evaluate the response event.
        // This is where Taint Propagation from tool output happens (if logic is added to SecurityCore).
        let decision = self.core.evaluate(event).await;

        if let SecurityDecision::AllowWithTransforms { taints_to_add, .. } = &decision {
            if !taints_to_add.is_empty() {
                if self.core.config.lean_logs {
                    println!("lilith >> tool: {} propagated taints: {:?}", tool_name, taints_to_add);
                } else {
                    tracing::info!("Tool {} propagated taints: {:?}", tool_name, taints_to_add);
                }
            }
        }

        self.core.log_audit(
            "HookPostTool",
            serde_json::json!({
                "tool_name": tool_name,
                "success": input.tool_output.is_some()
            }),
        );

        Ok(0)
    }
}
