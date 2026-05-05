// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::Config;
use crate::engine::cedar_evaluator::CedarEvaluator;
use crate::engine_core::auth;
use crate::engine_core::constants::jsonrpc;
use crate::engine_core::crypto::CryptoSigner;
use crate::engine_core::events::{SecurityDecision, SecurityEvent};
use crate::engine_core::models::{Decision, HistoryEntry, PolicyDefinition, PolicyRule};
use crate::engine_core::path_utils::extract_and_canonicalize_paths;
use anyhow::Result;
use cedar_policy::Decision as CedarDecision;

use crate::engine_core::audit::AuditLogger;
use crate::engine_core::telemetry::TelemetryHook;

/// Representative state of a security session, used for persistence.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
pub struct SessionState {
    /// Set of active security taints for the session.
    #[serde(default)]
    pub taints: HashSet<String>,
    /// Sequential history of tool executions and security decisions.
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
    /// Total tool calls made in this session lifetime (rate limiting).
    #[serde(default)]
    pub call_count: u32,
    /// Timestamps (epoch ms) of recent tool calls for sliding-window rate limiting.
    #[serde(default)]
    pub call_timestamps_ms: Vec<u64>,
    /// Seen request IDs with arrival timestamp (epoch ms) for replay nonce detection.
    #[serde(default)]
    pub seen_request_ids: HashMap<String, u64>,
}

/// Per-session security state: holds the active policy, taint set, history, and crypto signer.
pub struct SecurityCore {
    /// Shared runtime configuration (security level, policy path, audience, etc.).
    pub config: Arc<Config>,
    signer: CryptoSigner,
    audit: AuditLogger,
    /// HMAC-signed session identifier emitted to stderr on startup.
    pub session_id: String,
    /// The currently loaded security policy; `None` means no policy (fail-closed by default).
    pub policy: Option<PolicyDefinition>,
    /// The natively loaded Cedar policy evaluator.
    pub cedar_evaluator: Option<CedarEvaluator>,
    /// Dynamic tool capabilities discovered from upstream tools/list responses.
    pub dynamic_tool_classes: HashMap<String, Vec<String>>,
    taints: HashSet<String>,
    history: Vec<HistoryEntry>,
    call_count: u32,
    call_timestamps_ms: Vec<u64>,
    seen_request_ids: HashMap<String, u64>,
    /// Whether to strictly validate session HMAC signatures.
    pub validate_session_tokens: bool,
    telemetry: Option<Arc<dyn TelemetryHook>>,
}

impl SecurityCore {
    /// Create a new [`SecurityCore`] for a fresh session.
    ///
    /// Generates a new HMAC session ID and optionally opens an append-only audit log file.
    pub fn new(
        config: Arc<Config>,
        signer: CryptoSigner,
        audit_log_path: Option<PathBuf>,
    ) -> Result<Self, crate::engine_core::errors::InterceptorError> {
        let session_id = signer.generate_session_id()?;
        let audit = AuditLogger::new(signer.clone(), audit_log_path)?;
        Ok(Self {
            config,
            signer,
            audit,
            session_id,
            policy: None,
            cedar_evaluator: None,
            dynamic_tool_classes: HashMap::new(),
            taints: HashSet::new(),
            history: Vec::new(),
            call_count: 0,
            call_timestamps_ms: Vec::new(),
            seen_request_ids: HashMap::new(),
            validate_session_tokens: true,
            telemetry: None,
        })
    }

    /// Load a policy into the security core.
    ///
    /// If `protect_lethal_trifecta` is enabled in either the policy or the config, automatically
    /// appends the EXFILTRATION blocking rule that implements lethal-trifecta protection.
    pub fn set_policy(&mut self, mut policy: PolicyDefinition) {
        if policy.protect_lethal_trifecta || self.config.protect_lethal_trifecta {
            info!("Lethal trifecta protection enabled - auto-injecting EXFILTRATION blocking rule");
            policy.taint_rules.insert(
                0,
                PolicyRule {
                    tool: None,
                    tool_class: Some("EXFILTRATION".to_string()),
                    action: "CHECK_TAINT".to_string(),
                    tag: None,
                    forbidden_tags: None,
                    required_taints: Some(vec![
                        "ACCESS_PRIVATE".to_string(),
                        "UNTRUSTED_SOURCE".to_string(),
                    ]),
                    error: Some("Blocked by lethal trifecta protection".to_string()),
                    pattern: None,
                    match_args: None,
                    exceptions: None,
                },
            );
        }

        match crate::engine::yaml_to_cedar::CedarCompiler::compile(&policy) {
            Ok(policy_set) => {
                self.cedar_evaluator = Some(CedarEvaluator::new(policy_set));
                info!("Successfully compiled YAML policy to Cedar PolicySet");
            }
            Err(e) => {
                warn!(
                    "Failed to compile policy to Cedar: {}. Falling back to DENY ALL.",
                    e
                );
                // We no longer have a fallback evaluator, so if Cedar compilation fails, we fail closed.
            }
        }

        self.policy = Some(policy);
    }

    /// Load a native Cedar policy set into the security core.
    pub fn set_cedar_policy(&mut self, policy_set: cedar_policy::PolicySet) {
        self.cedar_evaluator = Some(CedarEvaluator::new(policy_set));
        info!("Successfully loaded Cedar PolicySet");
    }

    /// Register a telemetry hook for distributed tracing.
    ///
    /// Called by [`crate::mcp::server::McpMiddleware::with_telemetry`] — prefer
    /// that builder method over calling this directly.
    pub fn set_telemetry(&mut self, hook: Arc<dyn TelemetryHook>) {
        self.telemetry = Some(hook);
    }

    /// Emit a signed audit log entry for the current session.
    pub fn log_audit(&self, event_type: &str, details: serde_json::Value) {
        // Description: Executes the log_audit logic.
        self.audit.log(&self.session_id, event_type, details);
    }

    /// Export the current session state (taints, history, rate-limit counters, replay nonces).
    pub fn export_state(&self) -> SessionState {
        SessionState {
            taints: self.taints.clone(),
            history: self.history.clone(),
            call_count: self.call_count,
            call_timestamps_ms: self.call_timestamps_ms.clone(),
            seen_request_ids: self.seen_request_ids.clone(),
        }
    }

    /// Import session state from a [`SessionState`] object.
    pub fn import_state(&mut self, state: SessionState) {
        self.taints = state.taints;
        self.history = state.history;
        self.call_count = state.call_count;
        self.call_timestamps_ms = state.call_timestamps_ms;
        self.seen_request_ids = state.seen_request_ids;
    }

    /// Return the active taints for the current session.
    pub fn get_taints(&self) -> &HashSet<String> {
        &self.taints
    }

    /// Evaluate a [`SecurityEvent`] against the loaded policy and session state.
    ///
    /// Returns the [`SecurityDecision`] that should be applied to the request/response.
    /// Errors in policy evaluation produce `Deny` (fail-closed).
    #[must_use]
    pub async fn evaluate(&mut self, event: SecurityEvent) -> SecurityDecision {
        // Description: Executes the evaluate logic.
        match event {
            SecurityEvent::Handshake {
                client_info: _,
                audience_token,
                ..
            } => {
                if let Some(expected) = &self.config.expected_audience {
                    if let Some(token) = audience_token {
                        if let Err(e) = auth::validate_audience_claim(
                            &token,
                            expected,
                            self.config.jwt_secret.as_deref(),
                        ) {
                            warn!("Audience validation failed: {}", e);
                            return SecurityDecision::Deny {
                                error_code: jsonrpc::ERROR_AUTH,
                                reason: format!("Audience validation failed: {}", e),
                            };
                        }
                    } else {
                        warn!("Missing audience token required by policy");
                        return SecurityDecision::Deny {
                            error_code: jsonrpc::ERROR_AUTH,
                            reason: "Missing audience token".to_string(),
                        };
                    }
                }

                self.audit.log(
                    &self.session_id,
                    "SessionStart",
                    json!({ "timestamp": crate::utils::time::now() }),
                );

                if let Some(hook) = &self.telemetry {
                    hook.on_session_start(&self.session_id);
                }

                SecurityDecision::Allow
            }

            SecurityEvent::ToolRequest {
                tool_name,
                arguments,
                session_token,
                request_id,
            } => {
                if self.validate_session_tokens {
                    match session_token {
                        Some(token) => {
                            if token != self.session_id && self.validate_session_tokens {
                                warn!(
                                    "Session ID mismatch. Expected: {}, Got: {}",
                                    self.session_id, token
                                );
                                return SecurityDecision::Deny {
                                    error_code: jsonrpc::ERROR_AUTH,
                                    reason: "Session ID mismatch".to_string(),
                                };
                            }

                            if !self.signer.validate_session_id(&token) {
                                warn!("Invalid session token signature: {}", token);
                                return SecurityDecision::Deny {
                                    error_code: jsonrpc::ERROR_AUTH,
                                    reason: "Invalid Session ID".to_string(),
                                };
                            }
                        }
                        None => {
                            warn!("Missing session token");
                            return SecurityDecision::Deny {
                                error_code: jsonrpc::ERROR_AUTH,
                                reason: "Missing Session ID".to_string(),
                            };
                        }
                    }
                }

                // --- Replay nonce check ---
                if let Some(policy) = &self.policy {
                    if policy.replay_window_secs > 0 {
                        let id_key = request_id.to_string();
                        let now = crate::utils::time::now_ms();
                        let window_ms = policy.replay_window_secs * 1_000;
                        // Evict expired entries first.
                        self.seen_request_ids
                            .retain(|_, ts| now.saturating_sub(*ts) < window_ms);
                        if self.seen_request_ids.contains_key(&id_key) {
                            warn!("Replayed request ID: {}", id_key);
                            return SecurityDecision::Deny {
                                error_code: jsonrpc::ERROR_AUTH,
                                reason: format!("Replayed request id: {}", id_key),
                            };
                        }
                        self.seen_request_ids.insert(id_key, now);
                    }
                }

                // --- Rate limit check ---
                if let Some(policy) = &self.policy {
                    if let Some(ref rl) = policy.rate_limit {
                        let now_ms = crate::utils::time::now_ms();

                        self.call_count = self.call_count.saturating_add(1);
                        if let Some(max_session) = rl.max_calls_per_session {
                            if self.call_count > max_session {
                                warn!(
                                    "Session call limit exceeded: {}/{}",
                                    self.call_count, max_session
                                );
                                return SecurityDecision::Deny {
                                    error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                                    reason: format!(
                                        "Session call limit exceeded ({}/{})",
                                        self.call_count, max_session
                                    ),
                                };
                            }
                        }
                        if let Some(max_per_min) = rl.max_calls_per_minute {
                            self.call_timestamps_ms.push(now_ms);
                            // Keep only the last 60 seconds.
                            self.call_timestamps_ms
                                .retain(|ts| now_ms.saturating_sub(*ts) < 60_000);
                            if self.call_timestamps_ms.len() as u32 > max_per_min {
                                warn!(
                                    "Per-minute call limit exceeded: {}/{}",
                                    self.call_timestamps_ms.len(),
                                    max_per_min
                                );
                                return SecurityDecision::Deny {
                                    error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                                    reason: format!(
                                        "Per-minute call limit exceeded ({}/{})",
                                        self.call_timestamps_ms.len(),
                                        max_per_min
                                    ),
                                };
                            }
                        }
                    }
                }

                let tool_name_str = tool_name.into_inner_unchecked();
                let classes = self.classify_tool(&tool_name_str);

                let _eval_span = self
                    .telemetry
                    .as_ref()
                    .map(|h| h.begin_tool_evaluation(&self.session_id, &tool_name_str));

                let mut args_clone = arguments.inner().clone();
                let canonical_paths = extract_and_canonicalize_paths(&mut args_clone);

                let evaluator_result = if let Some(cedar_eval) = &self.cedar_evaluator {
                    let mut path_denied = None;
                    for path in &canonical_paths {
                        let path_arr = vec![path.clone()];
                        let res = cedar_eval.evaluate(
                            &self.session_id,
                            "resources/read",
                            &tool_name_str,
                            arguments.inner(),
                            &path_arr,
                            &self.taints,
                            &classes,
                        );
                        if let Ok(response) = res {
                            if response.decision() == CedarDecision::Deny {
                                path_denied =
                                    Some(format!("Path '{}' blocked by resource rules", path));
                                break;
                            }
                        }
                    }

                    if let Some(reason) = path_denied {
                        Ok(Decision::Denied { reason })
                    } else {
                        match cedar_eval.evaluate(
                            &self.session_id,
                            "tools/call",
                            &tool_name_str,
                            arguments.inner(),
                            &canonical_paths,
                            &self.taints,
                            &classes,
                        ) {
                            Ok(response) => {
                                if response.decision() == CedarDecision::Allow {
                                    let mut taints_to_add = vec![];
                                    let mut taints_to_remove = vec![];
                                    for policy_id in response.diagnostics().reason() {
                                        let id_str = policy_id.to_string();
                                        if let Some(tag) = id_str.strip_prefix("add_taint:") {
                                            if let Some((t, _)) = tag.split_once(':') {
                                                taints_to_add.push(t.to_string());
                                            }
                                        } else if let Some(tag) =
                                            id_str.strip_prefix("remove_taint:")
                                        {
                                            if let Some((t, _)) = tag.split_once(':') {
                                                taints_to_remove.push(t.to_string());
                                            }
                                        }
                                    }
                                    if taints_to_add.is_empty() && taints_to_remove.is_empty() {
                                        Ok(Decision::Allowed)
                                    } else {
                                        Ok(Decision::AllowedWithSideEffects {
                                            taints_to_add,
                                            taints_to_remove,
                                        })
                                    }
                                } else {
                                    let mut reason = "Denied by Cedar policy".to_string();
                                    for policy_id in response.diagnostics().reason() {
                                        if let Some(err_msg) =
                                            cedar_eval.get_policy_annotation(policy_id, "error")
                                        {
                                            reason = err_msg;
                                            break;
                                        }
                                    }
                                    Ok(Decision::Denied { reason })
                                }
                            }
                            Err(e) => Err(e),
                        }
                    }
                } else {
                    match self.config.security_level {
                        crate::config::SecurityLevel::AuditOnly => {
                            tracing::warn!(
                                tool = %tool_name_str,
                                "NO POLICY LOADED: Allowed only because security_level is {:?} (AuditOnly)",
                                self.config.security_level
                            );
                            Ok(Decision::Allowed)
                        }
                        crate::config::SecurityLevel::BlockParams => {
                            tracing::warn!(
                                tool = %tool_name_str,
                                "NO POLICY LOADED: Denying request because security_level is {:?} (Fail-Closed)",
                                self.config.security_level
                            );
                            Ok(Decision::Denied {
                                reason:
                                    "No security policy loaded. lilith-zero defaults to Deny-All."
                                        .to_string(),
                            })
                        }
                    }
                };

                match evaluator_result {
                    Ok(decision) => {
                        let sec_decision =
                            self.process_evaluator_decision(&tool_name_str, &classes, decision);
                        if let Some(hook) = &self.telemetry {
                            match &sec_decision {
                                SecurityDecision::Deny { reason, .. } => {
                                    hook.on_tool_decision(
                                        &self.session_id,
                                        &tool_name_str,
                                        false,
                                        Some(reason),
                                    );
                                }
                                _ => {
                                    hook.on_tool_decision(
                                        &self.session_id,
                                        &tool_name_str,
                                        true,
                                        None,
                                    );
                                }
                            }
                        }
                        sec_decision
                    }
                    Err(e) => {
                        warn!("Policy evaluation internal error: {}", e);
                        if let Some(hook) = &self.telemetry {
                            hook.on_policy_error(&self.session_id, &tool_name_str, &e.to_string());
                        }
                        SecurityDecision::Deny {
                            error_code: jsonrpc::ERROR_INTERNAL,
                            reason: format!("Policy error: {}", e),
                        }
                    }
                }
            }

            SecurityEvent::ResourceRequest {
                uri, session_token, ..
            } => {
                if self.validate_session_tokens {
                    if let Some(token) = session_token {
                        if !self.signer.validate_session_id(&token) {
                            return SecurityDecision::Deny {
                                error_code: jsonrpc::ERROR_AUTH,
                                reason: "Invalid Session ID".to_string(),
                            };
                        }
                    } else {
                        return SecurityDecision::Deny {
                            error_code: jsonrpc::ERROR_AUTH,
                            reason: "Missing Session ID".to_string(),
                        };
                    }
                }

                let mut taints_to_add = vec![];
                let uri_str = uri.clone().into_inner_unchecked();
                let mut uri_json = json!(uri_str);
                let canonical_paths = extract_and_canonicalize_paths(&mut uri_json);

                let allow_access = if let Some(cedar_eval) = &self.cedar_evaluator {
                    match cedar_eval.evaluate(
                        &self.session_id,
                        "resources/read",
                        &uri_str,
                        &json!({}),
                        &canonical_paths,
                        &self.taints,
                        &[],
                    ) {
                        Ok(response) => {
                            if response.decision() == CedarDecision::Allow {
                                for policy_id in response.diagnostics().reason() {
                                    let id_str = policy_id.to_string();
                                    if let Some(tag) = id_str.strip_prefix("add_taint:") {
                                        if let Some((t, _)) = tag.split_once(':') {
                                            taints_to_add.push(t.to_string());
                                        }
                                    }
                                }
                                true
                            } else {
                                let mut reason =
                                    format!("Access to resource denied by policy: {}", uri_str);
                                for policy_id in response.diagnostics().reason() {
                                    if let Some(err_msg) =
                                        cedar_eval.get_policy_annotation(policy_id, "error")
                                    {
                                        reason = err_msg;
                                        break;
                                    }
                                }
                                return SecurityDecision::Deny {
                                    error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                                    reason,
                                };
                            }
                        }
                        Err(e) => {
                            return SecurityDecision::Deny {
                                error_code: jsonrpc::ERROR_INTERNAL,
                                reason: format!("Policy error: {}", e),
                            };
                        }
                    }
                } else {
                    match self.config.security_level {
                        crate::config::SecurityLevel::AuditOnly => true,
                        _ => {
                            false // Fail Closed
                        }
                    }
                };

                if !allow_access {
                    return SecurityDecision::Deny {
                        error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                        reason: format!("Access to resource denied (Default Deny): {}", uri_str),
                    };
                }

                for t in &taints_to_add {
                    self.taints.insert(t.clone());
                }

                SecurityDecision::AllowWithTransforms {
                    taints_to_add,
                    taints_to_remove: vec![],
                    output_transforms: vec![],
                }
            }

            SecurityEvent::PromptRequest {
                request_id: _,
                prompt_name,
                arguments,
                session_token: _,
            } => {
                let prompt_name_str = prompt_name.into_inner_unchecked();
                let mut args_clone = arguments.inner().clone();
                let canonical_paths = extract_and_canonicalize_paths(&mut args_clone);

                let allow_access = if let Some(cedar_eval) = &self.cedar_evaluator {
                    matches!(cedar_eval.evaluate(
                        &self.session_id,
                        "prompts/get",
                        &prompt_name_str,
                        arguments.inner(),
                        &canonical_paths,
                        &self.taints,
                        &[],
                    ), Ok(res) if res.decision() == CedarDecision::Allow)
                } else {
                    false
                };

                if allow_access {
                    SecurityDecision::Allow
                } else {
                    SecurityDecision::Deny {
                        error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                        reason: format!("Prompt access denied by policy: {}", prompt_name_str),
                    }
                }
            }
            SecurityEvent::SamplingRequest {
                request_id: _,
                messages,
                session_token: _,
            } => {
                let mut messages_clone = messages.inner().clone();
                let canonical_paths = extract_and_canonicalize_paths(&mut messages_clone);

                let allow_access = if let Some(cedar_eval) = &self.cedar_evaluator {
                    matches!(cedar_eval.evaluate(
                        &self.session_id,
                        "sampling/createMessage",
                        "sampling",
                        messages.inner(),
                        &canonical_paths,
                        &self.taints,
                        &[],
                    ), Ok(res) if res.decision() == CedarDecision::Allow)
                } else {
                    false
                };

                if allow_access {
                    SecurityDecision::Allow
                } else {
                    SecurityDecision::Deny {
                        error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                        reason: "Sampling access denied by policy".to_string(),
                    }
                }
            }
            SecurityEvent::ToolResponse {
                tool_name: _,
                result: _,
                ..
            } => {
                // Currently, we don't have explicit "post-execution" rules in PolicyDefinition.
                // However, we can use this to apply transforms or propagate taints if added in the future.
                // For now, it's a no-op that allows state updates.
                SecurityDecision::Allow
            }
            SecurityEvent::Passthrough { .. } => SecurityDecision::Allow,
        }
    }

    /// Register dynamically discovered tool classes (e.g. from a tools/list response).
    pub fn register_tool_classes(&mut self, tool_name: &str, classes: Vec<String>) {
        if !classes.is_empty() {
            info!(
                "Registered dynamic classes for tool '{}': {:?}",
                tool_name, classes
            );
            self.dynamic_tool_classes
                .insert(tool_name.to_string(), classes);
        }
    }

    fn classify_tool(&self, name: &str) -> Vec<String> {
        let mut classes = self
            .policy
            .as_ref()
            .and_then(|p| p.tool_classes.get(name))
            .cloned()
            .unwrap_or_default();

        if let Some(dynamic) = self.dynamic_tool_classes.get(name) {
            for c in dynamic {
                if !classes.contains(c) {
                    classes.push(c.clone());
                }
            }
        }

        classes
    }

    fn process_evaluator_decision(
        &mut self,
        tool_name: &str,
        classes: &[String],
        decision: Decision,
    ) -> SecurityDecision {
        // Description: Executes the process_evaluator_decision logic.
        match decision {
            Decision::Allowed => {
                self.record_history(tool_name, classes);
                self.audit.log(
                    &self.session_id,
                    "Decision",
                    json!({
                        "tool_name": tool_name,
                        "decision": "ALLOW"
                    }),
                );

                SecurityDecision::Allow
            }
            Decision::Denied { reason } => {
                self.audit.log(
                    &self.session_id,
                    "Decision",
                    json!({
                        "tool_name": tool_name,
                        "decision": "DENY",
                        "details": {
                            "reason": reason,
                            "error_code": jsonrpc::ERROR_SECURITY_BLOCK
                        }
                    }),
                );
                if self.config.security_level_config().block_on_violation {
                    SecurityDecision::Deny {
                        error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                        reason,
                    }
                } else {
                    tracing::warn!(
                        tool = %tool_name,
                        %reason,
                        "POLICY VIOLATION: Allowed only because security_level is {:?} (AuditOnly)",
                        self.config.security_level
                    );
                    SecurityDecision::Allow
                }
            }
            Decision::AllowedWithSideEffects {
                taints_to_add,
                taints_to_remove,
            } => {
                self.record_history(tool_name, classes);

                for t in &taints_to_add {
                    self.taints.insert(t.clone());
                }
                for t in &taints_to_remove {
                    self.taints.remove(t);
                }

                self.audit.log(
                    &self.session_id,
                    "Decision",
                    json!({
                        "tool_name": tool_name,
                        "decision": "ALLOW_WITH_SIDE_EFFECTS",
                        "details": {
                            "taints_to_add": taints_to_add,
                            "taints_to_remove": taints_to_remove
                        }
                    }),
                );

                SecurityDecision::AllowWithTransforms {
                    taints_to_add,
                    taints_to_remove,
                    output_transforms: vec![],
                }
            }
        }
    }

    fn record_history(&mut self, tool: &str, classes: &[String]) {
        // Description: Executes the record_history logic.
        self.history.push(HistoryEntry {
            tool: tool.to_string(),
            classes: classes.to_vec(),
            timestamp: crate::utils::time::now(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_core::events::{SecurityDecision, SecurityEvent};
    use crate::engine_core::taint::Tainted;
    use crate::engine_core::types::TaintedString;

    #[tokio::test]
    async fn test_security_core_flow() {
        // Description: Executes the test_security_core_flow logic.
        let config = Arc::new(Config::default());
        let signer = CryptoSigner::try_new().unwrap();
        let mut core = SecurityCore::new(config, signer, None).unwrap();

        let event = SecurityEvent::Handshake {
            protocol_version: "2024-11-05".to_string(),
            client_info: serde_json::Value::Null,
            audience_token: None,
            capabilities: serde_json::Value::Null,
        };
        let decision = core.evaluate(event).await;
        match decision {
            SecurityDecision::Allow => {}
            _ => panic!("Expected Allow for handshake"),
        }

        let tool_event = SecurityEvent::ToolRequest {
            request_id: serde_json::Value::String("1".to_string()),
            tool_name: TaintedString::new("read_file".to_string()),
            arguments: Tainted::new(serde_json::Value::Null, vec![]),
            session_token: None,
        };
        let decision = core.evaluate(tool_event).await;
        match decision {
            SecurityDecision::Deny { reason, .. } => {
                assert!(reason.contains("Missing Session ID"));
            }
            _ => panic!("Expected Deny for missing session"),
        }

        let valid_token = core.session_id.clone();

        let tool_event = SecurityEvent::ToolRequest {
            request_id: serde_json::Value::String("2".to_string()),
            tool_name: TaintedString::new("read_file".to_string()),
            arguments: Tainted::new(serde_json::Value::Null, vec![]),
            session_token: Some(valid_token),
        };

        let decision = core.evaluate(tool_event.clone()).await;
        match decision {
            SecurityDecision::Deny { reason, .. } => {
                assert!(reason.contains("No security policy loaded"));
            }
            _ => panic!("Expected Deny for missing policy (Fail Closed)"),
        }

        let audit_config = Config {
            security_level: crate::config::SecurityLevel::AuditOnly,
            ..Config::default()
        };

        let mut audit_core = SecurityCore::new(
            Arc::new(audit_config),
            CryptoSigner::try_new().unwrap(),
            None,
        )
        .unwrap();
        let valid_token_audit = audit_core.session_id.clone();
        let tool_event_audit = SecurityEvent::ToolRequest {
            request_id: serde_json::Value::String("3".to_string()),
            tool_name: TaintedString::new("read_file".to_string()),
            arguments: Tainted::new(serde_json::Value::Null, vec![]),
            session_token: Some(valid_token_audit),
        };

        let decision_audit = audit_core.evaluate(tool_event_audit).await;
        match decision_audit {
            SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {}
            other => {
                eprintln!("In AuditOnly mode, got unexpected decision: {:?}", other);
                panic!("Expected Allow for AuditOnly mode");
            }
        }
    }
}
