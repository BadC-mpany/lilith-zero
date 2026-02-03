//! Security Core.
//!
//! The central brain of Sentinel. It maintains security state (taints, history),
//! evaluates policies, and emits audit logs. It is pure software logic and does not
//! know about stdio, network sockets, or specific JSON-RPC versions.

use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, warn};
use serde_json::json;

use crate::config::Config;
use crate::core::crypto::CryptoSigner;
use crate::core::events::{SecurityEvent, SecurityDecision, OutputTransform};
use crate::core::models::{Decision, HistoryEntry, PolicyDefinition, TrifectaClass};
use crate::engine::evaluator::PolicyEvaluator;
use crate::core::auth;
use crate::core::constants::jsonrpc;

const TRIFECTA_BLOCK_REASON: &str =
    "Policy violation: external communication blocked by lethal trifecta protection.";

#[derive(Debug, Default)]
struct TrifectaState {
    access_private: bool,
    untrusted_source: bool,
}

pub struct SecurityCore {
    pub config: Arc<Config>,
    signer: CryptoSigner,
    pub session_id: String,
    pub policy: Option<PolicyDefinition>,
    taints: HashSet<String>,
    history: Vec<HistoryEntry>,
    trifecta_state: TrifectaState,
}

impl SecurityCore {
    pub fn new(config: Arc<Config>, signer: CryptoSigner) -> Result<Self, crate::core::errors::InterceptorError> {
        let session_id = signer.generate_session_id()?;
        Ok(Self {
            config,
            signer,
            session_id,
            policy: None,
            taints: HashSet::new(),
            history: Vec::new(),
            trifecta_state: TrifectaState::default(),
        })
    }

    pub fn set_policy(&mut self, policy: PolicyDefinition) {
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
                // 1. Validate Audience Binding (if configured)
                if let Some(expected) = &self.config.expected_audience {
                    if let Some(token) = audience_token {
                         if let Err(e) = auth::validate_audience_claim(&token, expected, self.config.jwt_secret.as_deref()) {
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
                info!(
                    target: "audit",
                    event_type = "SessionStart",
                    session_id = %self.session_id,
                    timestamp = %crate::utils::time::now(),
                );
                
                SecurityDecision::Allow
            },
            
            SecurityEvent::ToolRequest { 
                tool_name, 
                arguments, 
                session_token, 
                .. 
            } => {
                 // 1. Validate Session
                 if self.config.security_level_config().session_validation {
                     match session_token {
                         Some(token) => {
                             // Strict check: Must match the current session ID exactly.
                             if token != self.session_id {
                                  warn!("Session ID mismatch. Expected: {}, Got: {}", self.session_id, token);
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
                         },
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
                 let classes = self.classify_tool(&tool_name);
                 let trifecta_classes = self.trifecta_classes_for_tool(&tool_name);

                 // 2a. Enforce lethal trifecta protection (exfil-only)
                 if self.should_block_external(&trifecta_classes) {
                     warn!(
                         "Lethal trifecta protection blocked external communication for tool: {}",
                         tool_name
                     );
                     return SecurityDecision::Deny {
                         error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                         reason: TRIFECTA_BLOCK_REASON.to_string(),
                     };
                 }
                 
                 // 3. Evaluate Policy
                 let evaluator_result = if let Some(policy) = &self.policy {
                     PolicyEvaluator::evaluate_with_args(
                        policy,
                        &tool_name,
                        &classes,
                        &self.history,
                        &self.taints,
                        &arguments
                     ).await
                 } else {
                     // Fail Closed unless in AuditOnly mode
                     // "Google-grade" best practice: Default Deny.
                     match self.config.security_level {
                         crate::config::SecurityLevel::AuditOnly => {
                             warn!("No policy loaded. allowing request due to AuditOnly mode.");
                             Ok(Decision::Allowed)
                         },
                         _ => {
                             warn!("No policy loaded. Denying request due to strict security settings.");
                             Ok(Decision::Denied { 
                                 reason: "No security policy loaded. Sentinel defaults to Deny-All.".to_string() 
                             })
                         }
                     }
                 };

                 match evaluator_result {
                     Ok(decision) => self.process_evaluator_decision(
                         &tool_name,
                         &classes,
                         &trifecta_classes,
                         decision,
                     ),
                     Err(e) => {
                         warn!("Policy evaluation internal error: {}", e);
                         SecurityDecision::Deny {
                             error_code: jsonrpc::ERROR_INTERNAL, // Internal error
                             reason: format!("Policy error: {}", e),
                         }
                     }
                 }
            },
            
            SecurityEvent::ResourceRequest { uri, session_token, .. } => {
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
                
                if let Some(policy) = &self.policy {
                    for rule in &policy.resource_rules {
                         if self.match_resource_pattern(&uri, &rule.uri_pattern) {
                             if rule.action == "BLOCK" {
                                 return SecurityDecision::Deny {
                                     error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                                     reason: format!("Resource blocked by rule: {}", rule.uri_pattern),
                                 };
                             } else if rule.action == "ALLOW" {
                                 allow_access = true;
                                 break;
                             }
                         }
                    }
                } else {
                    // No policy loaded = Default Deny checking mode
                     match self.config.security_level {
                         crate::config::SecurityLevel::AuditOnly => {
                             allow_access = true;
                         },
                         _ => {
                             allow_access = false; // Fail Closed
                         }
                     }
                }

                if !allow_access {
                     return SecurityDecision::Deny {
                        error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                        reason: format!("Access to resource denied (Default Deny): {}", uri),
                    };
                }

                self.note_access_private_resource();

                 SecurityDecision::AllowWithTransforms {
                    taints_to_add: vec![],
                    taints_to_remove: vec![],
                    output_transforms: vec![OutputTransform::Spotlight { json_paths: vec![] }], // contents spotlighting
                }
            },

            SecurityEvent::Passthrough { .. } => SecurityDecision::Allow,
        }
    }

    fn classify_tool(&self, name: &str) -> Vec<String> {
         if name.starts_with("read_") || name.starts_with("get_") {
            vec!["READ".to_string()]
        } else if name.starts_with("write_") || name.starts_with("delete_") {
            vec!["WRITE".to_string()]
        } else {
            vec![]
        }
    }

    fn process_evaluator_decision(
        &mut self,
        tool_name: &str,
        classes: &[String],
        trifecta_classes: &[TrifectaClass],
        decision: Decision,
    ) -> SecurityDecision {
        match decision {
            Decision::Allowed => {
                self.record_history(tool_name, classes);
                self.update_trifecta_state(trifecta_classes);
                info!(
                    target: "audit",
                    event_type = "Decision",
                    session_id = %self.session_id,
                    timestamp = %crate::utils::time::now(),
                    tool_name = %tool_name,
                    decision = "ALLOW",
                );
                
                // If spotlighting is enabled, we apply it
                if self.config.security_level_config().spotlighting {
                     SecurityDecision::AllowWithTransforms {
                        taints_to_add: vec![],
                        taints_to_remove: vec![],
                        output_transforms: vec![OutputTransform::Spotlight { json_paths: vec![] }]
                    }
                } else {
                    SecurityDecision::Allow
                }
            },
            Decision::Denied { reason } => {
                 info!(
                    target: "audit",
                    event_type = "Decision",
                    session_id = %self.session_id,
                    timestamp = %crate::utils::time::now(),
                    tool_name = %tool_name,
                    decision = "DENY",
                    details = %json!({
                        "reason": reason,
                        "error_code": jsonrpc::ERROR_SECURITY_BLOCK
                    })
                );
                SecurityDecision::Deny {
                    error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                    reason,
                }
            },
            Decision::AllowedWithSideEffects { taints_to_add, taints_to_remove } => {
                self.record_history(tool_name, classes);
                self.update_trifecta_state(trifecta_classes);
                
                for t in &taints_to_add { self.taints.insert(t.clone()); }
                for t in &taints_to_remove { self.taints.remove(t); }

                let _details = serde_json::json!({
                    "taints_added": taints_to_add,
                    "taints_removed": taints_to_remove
                });
                
                info!(
                    target: "audit",
                    event_type = "Decision",
                    session_id = %self.session_id,
                    timestamp = %crate::utils::time::now(),
                    tool_name = %tool_name,
                    decision = "ALLOW_WITH_SIDE_EFFECTS",
                    details = %json!({
                        "taints_to_add": taints_to_add,
                        "taints_to_remove": taints_to_remove
                    })
                );
                if self.config.security_level_config().spotlighting {
                     SecurityDecision::AllowWithTransforms {
                        taints_to_add,
                        taints_to_remove,
                        output_transforms: vec![OutputTransform::Spotlight { json_paths: vec![] }]
                    }
                } else {
                     SecurityDecision::AllowWithTransforms {
                        taints_to_add,
                        taints_to_remove,
                        output_transforms: vec![]
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

    fn trifecta_enabled(&self) -> bool {
        self.policy
            .as_ref()
            .map(|policy| policy.enforce_trifecta_protection)
            .unwrap_or(false)
    }

    fn trifecta_classes_for_tool(&self, name: &str) -> Vec<TrifectaClass> {
        if !self.trifecta_enabled() {
            return Vec::new();
        }
        self.policy
            .as_ref()
            .and_then(|policy| policy.trifecta_tool_classes.get(name).cloned())
            .unwrap_or_default()
    }

    fn should_block_external(&self, classes: &[TrifectaClass]) -> bool {
        if !self.trifecta_enabled() {
            return false;
        }
        let has_external = classes
            .iter()
            .any(|class| *class == TrifectaClass::ExternalCommunication);
        if !has_external {
            return false;
        }
        let has_access_private = self.trifecta_state.access_private
            || classes
                .iter()
                .any(|class| *class == TrifectaClass::AccessPrivate);
        let has_untrusted_source = self.trifecta_state.untrusted_source
            || classes
                .iter()
                .any(|class| *class == TrifectaClass::UntrustedSource);
        has_access_private && has_untrusted_source
    }

    fn update_trifecta_state(&mut self, classes: &[TrifectaClass]) {
        if !self.trifecta_enabled() {
            return;
        }
        for class in classes {
            match class {
                TrifectaClass::AccessPrivate => {
                    self.trifecta_state.access_private = true;
                }
                TrifectaClass::UntrustedSource => {
                    self.trifecta_state.untrusted_source = true;
                }
                TrifectaClass::ExternalCommunication => {}
            }
        }
    }

    fn note_access_private_resource(&mut self) {
        if self.trifecta_enabled() {
            self.trifecta_state.access_private = true;
        }
    }

    fn match_resource_pattern(&self, uri: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix("*") {
             return uri.starts_with(prefix);
        }
        uri == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::events::SecurityEvent;
    use crate::mcp::sandbox::SandboxPolicy;
    use std::collections::HashMap;

    fn build_trifecta_policy(enforce: bool) -> PolicyDefinition {
        let mut static_rules = HashMap::new();
        static_rules.insert("read_private".to_string(), "ALLOW".to_string());
        static_rules.insert("fetch_web".to_string(), "ALLOW".to_string());
        static_rules.insert("send_external".to_string(), "ALLOW".to_string());

        let mut trifecta_tool_classes = HashMap::new();
        trifecta_tool_classes.insert(
            "read_private".to_string(),
            vec![TrifectaClass::AccessPrivate],
        );
        trifecta_tool_classes.insert(
            "fetch_web".to_string(),
            vec![TrifectaClass::UntrustedSource],
        );
        trifecta_tool_classes.insert(
            "send_external".to_string(),
            vec![TrifectaClass::ExternalCommunication],
        );

        PolicyDefinition {
            id: "test-policy".to_string(),
            customer_id: "test-customer".to_string(),
            name: "trifecta-policy".to_string(),
            version: 1,
            static_rules,
            taint_rules: vec![],
            enforce_trifecta_protection: enforce,
            trifecta_tool_classes,
            created_at: None,
            resource_rules: vec![],
            sandbox: Some(SandboxPolicy::default()),
        }
    }
    
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
             SecurityDecision::Allow => {},
             _ => panic!("Expected Allow for handshake"),
        }
        
        // 2. Tool Request (No Session) -> Should Fail
        let tool_event = SecurityEvent::ToolRequest {
            request_id: serde_json::Value::String("1".to_string()),
            tool_name: "read_file".to_string(),
            arguments: serde_json::Value::Null,
            session_token: None,
        };
        let decision = core.evaluate(tool_event).await;
        match decision {
            SecurityDecision::Deny { reason, .. } => {
                assert!(reason.contains("Missing Session ID"));
            },
            _ => panic!("Expected Deny for missing session"),
        }

        // 3. Tool Request (Valid Session, No Policy) -> Should Fail Closed (Default Deny)
        // We simulate a valid session check pass by mocking or... 
        // We can't easily mock signature without key.
        // But we can test `SecurityLevel::AuditOnly` fallback if we could inject config.
        // Let's create a core with AuditOnly and see if it allows.
        
        let mut audit_config = Config::default();
        audit_config.security_level = crate::config::SecurityLevel::AuditOnly;
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
            tool_name: "read_file".to_string(),
            arguments: serde_json::Value::Null,
            session_token: Some(valid_token),
        };
        
        // With Default Config (BlockParams) -> Should Deny (Fail Closed)
        let decision = core.evaluate(tool_event.clone()).await;
        match decision {
            SecurityDecision::Deny { reason, .. } => {
                assert!(reason.contains("No security policy loaded"));
            },
            _ => panic!("Expected Deny for missing policy (Fail Closed)"),
        }
        
       // With Audit Config -> Should Allow (Log Only)
       let mut audit_core = SecurityCore::new(Arc::new(audit_config), CryptoSigner::try_new().unwrap()).unwrap();
       let valid_token_audit = audit_core.session_id.clone();
       let tool_event_audit = SecurityEvent::ToolRequest {
            request_id: serde_json::Value::String("3".to_string()),
            tool_name: "read_file".to_string(),
            arguments: serde_json::Value::Null,
            session_token: Some(valid_token_audit),
        };
        
        let decision_audit = audit_core.evaluate(tool_event_audit).await;
        match decision_audit {
             SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {},
             _ => panic!("Expected Allow for AuditOnly mode"),
        }
    }

    #[tokio::test]
    async fn test_trifecta_blocks_external_after_access_and_untrusted() {
        let config = Arc::new(Config::default());
        let signer = CryptoSigner::try_new().unwrap();
        let mut core = SecurityCore::new(config, signer).unwrap();
        core.set_policy(build_trifecta_policy(true));

        let token = core.session_id.clone();

        let read_event = SecurityEvent::ToolRequest {
            request_id: serde_json::Value::String("1".to_string()),
            tool_name: "read_private".to_string(),
            arguments: serde_json::Value::Null,
            session_token: Some(token.clone()),
        };
        let decision = core.evaluate(read_event).await;
        assert!(matches!(
            decision,
            SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. }
        ));

        let untrusted_event = SecurityEvent::ToolRequest {
            request_id: serde_json::Value::String("2".to_string()),
            tool_name: "fetch_web".to_string(),
            arguments: serde_json::Value::Null,
            session_token: Some(token.clone()),
        };
        let decision = core.evaluate(untrusted_event).await;
        assert!(matches!(
            decision,
            SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. }
        ));

        let exfil_event = SecurityEvent::ToolRequest {
            request_id: serde_json::Value::String("3".to_string()),
            tool_name: "send_external".to_string(),
            arguments: serde_json::Value::Null,
            session_token: Some(token),
        };
        let decision = core.evaluate(exfil_event).await;
        match decision {
            SecurityDecision::Deny { error_code, reason } => {
                assert_eq!(error_code, jsonrpc::ERROR_SECURITY_BLOCK);
                assert_eq!(reason, TRIFECTA_BLOCK_REASON);
            }
            _ => panic!("Expected trifecta block for external communication"),
        }
    }

    #[tokio::test]
    async fn test_trifecta_allows_external_without_both_flags() {
        let config = Arc::new(Config::default());
        let signer = CryptoSigner::try_new().unwrap();
        let mut core = SecurityCore::new(config, signer).unwrap();
        core.set_policy(build_trifecta_policy(true));

        let token = core.session_id.clone();

        let read_event = SecurityEvent::ToolRequest {
            request_id: serde_json::Value::String("1".to_string()),
            tool_name: "read_private".to_string(),
            arguments: serde_json::Value::Null,
            session_token: Some(token.clone()),
        };
        let decision = core.evaluate(read_event).await;
        match decision {
            SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {}
            _ => panic!("Expected allow for access_private tool"),
        }

        let exfil_event = SecurityEvent::ToolRequest {
            request_id: serde_json::Value::String("2".to_string()),
            tool_name: "send_external".to_string(),
            arguments: serde_json::Value::Null,
            session_token: Some(token),
        };
        let decision = core.evaluate(exfil_event).await;
        match decision {
            SecurityDecision::Allow | SecurityDecision::AllowWithTransforms { .. } => {}
            _ => panic!("Expected allow without untrusted_source"),
        }
    }
}
