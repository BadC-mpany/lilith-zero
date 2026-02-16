// Copyright 2026 BadCompany
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Security Core.
//!
//! The central brain of lilith-zero. It maintains security state (taints, history),
//! evaluates policies, and emits audit logs. It is pure software logic and does not
//! know about stdio, network sockets, or specific JSON-RPC versions.

use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::Config;
use crate::engine::evaluator::PolicyEvaluator;
use crate::engine_core::auth;
use crate::engine_core::constants::jsonrpc;
use crate::engine_core::crypto::CryptoSigner;
use crate::engine_core::events::{OutputTransform, SecurityDecision, SecurityEvent};
use crate::engine_core::models::{Decision, HistoryEntry, PolicyDefinition, PolicyRule};
use anyhow::Result;

use crate::engine_core::audit::AuditLogger;

pub struct SecurityCore {
    pub config: Arc<Config>,
    signer: CryptoSigner,
    audit: AuditLogger,
    pub session_id: String,
    pub policy: Option<PolicyDefinition>,
    /// Set of active taint tags in the session
    taints: HashSet<String>,
    history: Vec<HistoryEntry>,
}

impl SecurityCore {
    pub fn new(
        config: Arc<Config>,
        signer: CryptoSigner,
    ) -> Result<Self, crate::engine_core::errors::InterceptorError> {
        let session_id = signer.generate_session_id()?;
        let audit = AuditLogger::new(signer.clone());
        Ok(Self {
            config,
            signer,
            audit,
            session_id,
            policy: None, // Changed        _policy: &SandboxPolicy, to policy: None to match struct definition
            taints: HashSet::new(),
            history: Vec::new(),
        })
    }

    pub fn set_policy(&mut self, mut policy: PolicyDefinition) {
        // Auto-inject lethal trifecta protection rule if enabled
        if policy.protect_lethal_trifecta || self.config.protect_lethal_trifecta {
            info!("Lethal trifecta protection enabled - auto-injecting EXFILTRATION blocking rule");
            policy.taint_rules.push(PolicyRule {
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
                exceptions: None,
            });
        }
        self.policy = Some(policy);
    }

    /// Primary entry point for all security decisions.
    pub async fn evaluate(&mut self, event: SecurityEvent) -> SecurityDecision {
        match event {
            SecurityEvent::Handshake {
                client_info: _,
                audience_token,
                ..
            } => {
                // ... audience validation ...
                // 1. Validate Audience Binding (if configured)
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

                // Log Session Start
                self.audit.log(
                    &self.session_id,
                    "SessionStart",
                    json!({ "timestamp": crate::utils::time::now() }),
                );

                SecurityDecision::Allow
            }

            SecurityEvent::ToolRequest {
                tool_name,
                arguments,
                session_token,
                ..
            } => {
                // ... session validation ...
                // 1. Validate Session
                if self.config.security_level_config().session_validation {
                    match session_token {
                        Some(token) => {
                            // Strict check: Must match the current session ID exactly.
                            if token != self.session_id {
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

                // 2. Classify Tool
                // We extract the tool name string for classification.
                let tool_name_str = tool_name.into_inner();
                let classes = self.classify_tool(&tool_name_str);

                // 3. Evaluate Policy
                let evaluator_result = if let Some(policy) = &self.policy {
                    PolicyEvaluator::evaluate_with_args(
                        policy,
                        &tool_name_str,
                        &classes,
                        &self.history,
                        &self.taints,
                        arguments.inner(), // Helper to get reference without consuming? Tainted is defined where?
                    )
                    .await
                } else {
                    match self.config.security_level {
                        crate::config::SecurityLevel::AuditOnly => {
                            warn!("No security policy loaded. Allowing request due to AuditOnly mode.");
                            Ok(Decision::Allowed)
                        }
                        crate::config::SecurityLevel::BlockParams => {
                            warn!("No security policy loaded. Denying request due to strict security settings (Fail-Closed).");
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
                        self.process_evaluator_decision(&tool_name_str, &classes, decision)
                    }
                    Err(e) => {
                        warn!("Policy evaluation internal error: {}", e);
                        SecurityDecision::Deny {
                            error_code: jsonrpc::ERROR_INTERNAL, // Internal error
                            reason: format!("Policy error: {}", e),
                        }
                    }
                }
            }

            SecurityEvent::ResourceRequest {
                uri, session_token, ..
            } => {
                // ... resource implementation ...
                // Similar session validation
                if self.config.security_level_config().session_validation {
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

                // Resource Policy Enforcement (Fail Closed)
                let mut allow_access = false;
                let mut taints_to_add = vec![];

                if let Some(policy) = &self.policy {
                    for rule in &policy.resource_rules {
                        if self.match_resource_pattern(&uri.clone().into_inner(), &rule.uri_pattern)
                        {
                            if rule.action == "BLOCK" {
                                return SecurityDecision::Deny {
                                    error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                                    reason: format!(
                                        "Resource blocked by rule: {}",
                                        rule.uri_pattern
                                    ),
                                };
                            } else if rule.action == "ALLOW" {
                                allow_access = true;
                                // Collect taints from matching rule
                                if let Some(ref taints) = rule.taints_to_add {
                                    taints_to_add.extend(taints.clone());
                                }
                                break; // First match wins
                            }
                        }
                    }
                } else {
                    // No policy loaded = Default Deny checking mode
                    match self.config.security_level {
                        crate::config::SecurityLevel::AuditOnly => {
                            allow_access = true;
                        }
                        _ => {
                            allow_access = false; // Fail Closed
                        }
                    }
                }

                if !allow_access {
                    return SecurityDecision::Deny {
                        error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                        reason: format!(
                            "Access to resource denied (Default Deny): {}",
                            uri.into_inner()
                        ),
                    };
                }

                // Apply taints to session state
                for t in &taints_to_add {
                    self.taints.insert(t.clone());
                }

                SecurityDecision::AllowWithTransforms {
                    taints_to_add,
                    taints_to_remove: vec![],
                    output_transforms: vec![OutputTransform::Spotlight { json_paths: vec![] }], // contents spotlighting
                }
            }

            SecurityEvent::Passthrough { .. } => SecurityDecision::Allow,
        }
    }

    fn classify_tool(&self, name: &str) -> Vec<String> {
        if name.starts_with("read_") || name.starts_with("get_") {
            vec!["READ".to_string()]
        } else if name.starts_with("write_") || name.starts_with("delete_") {
            vec!["WRITE".to_string()]
        } else if matches!(name, "curl" | "wget" | "fetch" | "requests" | "http") {
             vec!["EXFILTRATION".to_string(), "NETWORK".to_string()]
        } else {
            vec![]
        }
    }

    fn process_evaluator_decision(
        &mut self,
        tool_name: &str,
        classes: &[String],
        decision: Decision,
    ) -> SecurityDecision {
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

                // If spotlighting is enabled, we apply it
                if self.config.security_level_config().spotlighting {
                    SecurityDecision::AllowWithTransforms {
                        taints_to_add: vec![],
                        taints_to_remove: vec![],
                        output_transforms: vec![OutputTransform::Spotlight { json_paths: vec![] }],
                    }
                } else {
                    SecurityDecision::Allow
                }
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
                SecurityDecision::Deny {
                    error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                    reason,
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

                if self.config.security_level_config().spotlighting {
                    SecurityDecision::AllowWithTransforms {
                        taints_to_add,
                        taints_to_remove,
                        output_transforms: vec![OutputTransform::Spotlight { json_paths: vec![] }],
                    }
                } else {
                    SecurityDecision::AllowWithTransforms {
                        taints_to_add,
                        taints_to_remove,
                        output_transforms: vec![],
                    }
                }
            }
        }
    }

    fn record_history(&mut self, tool: &str, classes: &[String]) {
        self.history.push(HistoryEntry {
            tool: tool.to_string(),
            classes: classes.to_vec(),
            timestamp: crate::utils::time::now(),
        });
    }

    fn match_resource_pattern(&self, uri: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix("*") {
            return uri.starts_with(prefix);
        }
        if let Some(suffix) = pattern.strip_prefix("*") {
            return uri.ends_with(suffix);
        }
        if let Some((prefix, suffix)) = pattern.split_once('*') {
            return uri.starts_with(prefix) && uri.ends_with(suffix);
        }
        uri == pattern
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
        let config = Arc::new(Config::default());
        let signer = CryptoSigner::try_new().unwrap();
        let mut core = SecurityCore::new(config, signer).unwrap();

        // 1. Handshake
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

        // 2. Tool Request (No Session) -> Should Fail
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

        // 3. Tool Request (Valid Session, No Policy) -> Should Fail Closed (Default Deny)
        // We simulate a valid session check pass by mocking or...
        // We can't easily mock signature without key.
        // But we can test `SecurityLevel::AuditOnly` fallback if we could inject config.
        // Let's create a core with AuditOnly and see if it allows.

        // Turn off session validation for this test to bypass signature check?
        // No, AuditOnly logic in config.rs sets session_validation = true.
        // So we still need a valid token.
        // We can generate one if we have the signer.
        // Core has a signer. Can we clone it? No, private.
        // Tests are in `mod tests` inside `src/core/security_core.rs`?
        // Yes, `super::*` means we are inside the file.
        // So we CAN access private fields of `core`!

        // Fix: core.session_id IS the valid token string. Check equality (which we just enforced).
        let valid_token = core.session_id.clone();

        let tool_event = SecurityEvent::ToolRequest {
            request_id: serde_json::Value::String("2".to_string()),
            tool_name: TaintedString::new("read_file".to_string()),
            arguments: Tainted::new(serde_json::Value::Null, vec![]),
            session_token: Some(valid_token),
        };

        // With Default Config (BlockParams) -> Should Deny (Fail Closed)
        let decision = core.evaluate(tool_event.clone()).await;
        match decision {
            SecurityDecision::Deny { reason, .. } => {
                assert!(reason.contains("No security policy loaded"));
            }
            _ => panic!("Expected Deny for missing policy (Fail Closed)"),
        }

        // With Audit Config -> Should Allow (Log Only)
        let audit_config = Config {
            security_level: crate::config::SecurityLevel::AuditOnly,
            ..Config::default()
        };

        let mut audit_core =
            SecurityCore::new(Arc::new(audit_config), CryptoSigner::try_new().unwrap()).unwrap();
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
