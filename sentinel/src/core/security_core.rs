//! Security Core.
//!
//! The central brain of Sentinel. It maintains security state (taints, history),
//! evaluates policies, and emits audit logs. It is pure software logic and does not
//! know about stdio, network sockets, or specific JSON-RPC versions.

use std::collections::HashSet;
use std::sync::Arc;
use tracing::warn;

use crate::config::Config;
use crate::core::crypto::CryptoSigner;
use crate::core::events::{SecurityEvent, SecurityDecision, OutputTransform};
use crate::core::models::{Decision, HistoryEntry, PolicyDefinition};
use crate::engine::evaluator::PolicyEvaluator;
use crate::utils::audit_logger::{AuditLogger, AuditEntry, AuditEventType};
use crate::core::auth;
use crate::constants::jsonrpc;

pub struct SecurityCore {
    pub config: Arc<Config>,
    signer: CryptoSigner,
    pub session_id: String,
    pub policy: Option<PolicyDefinition>,
    taints: HashSet<String>,
    history: Vec<HistoryEntry>,
}

impl SecurityCore {
    pub fn new(config: Arc<Config>, signer: CryptoSigner) -> Self {
        let session_id = signer.generate_session_id();
        Self {
            config,
            signer,
            session_id,
            policy: None,
            taints: HashSet::new(),
            history: Vec::new(),
        }
    }

    pub fn set_policy(&mut self, policy: PolicyDefinition) {
        self.policy = Some(policy);
    }

    /// Primary entry point for all security decisions.
    pub async fn evaluate(&mut self, event: SecurityEvent) -> SecurityDecision {
        match event {
            SecurityEvent::Handshake {
                client_info,
                audience_token,
                ..
            } => {
                // 1. Validate Audience Binding (if configured)
                if let Some(expected) = &self.config.expected_audience {
                    if let Some(token) = audience_token {
                         if let Err(e) = auth::validate_audience_claim(&token, expected) {
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
                AuditLogger::log(AuditEntry {
                    timestamp: AuditLogger::now(),
                    session_id: self.session_id.clone(),
                    event_type: AuditEventType::SessionStart,
                    tool: None,
                    decision: None,
                    details: Some(client_info),
                });
                
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
                             if !self.signer.validate_session_id(&token) {
                                  warn!("Invalid session token: {}", token);
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
                     // Default deny if no policy loaded? Or allow if fallback?
                     // Main.rs currently loads a default ALLOW ALL policy if none found.
                     // So specific policy logic handles fallback. Here, if None, we assume strictly deny to be safe?
                     // Actually, main.rs ensures policy is Some. Let's assume safe default Allow for MVP/fallback.
                     // But strictly speaking, Sentinel should likely have a policy.
                     Ok(Decision::Allowed)
                 };

                 match evaluator_result {
                     Ok(decision) => self.process_evaluator_decision(&tool_name, &classes, decision),
                     Err(e) => {
                         warn!("Policy evaluation internal error: {}", e);
                         SecurityDecision::Deny {
                             error_code: -32603, // Internal error
                             reason: format!("Policy error: {}", e),
                         }
                     }
                 }
            },
            
            SecurityEvent::ResourceRequest { uri: _, session_token, .. } => {
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
                
                // For resources, we currently don't have granular policy rules in the MVP models. 
                // We default to Allow, but apply Output Transformations (Spotlighting).
                // TODO: Add Resource Rules to PolicyEvaluator
                
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

    fn process_evaluator_decision(&mut self, tool_name: &str, classes: &[String], decision: Decision) -> SecurityDecision {
        match decision {
            Decision::Allowed => {
                self.record_history(tool_name, classes);
                AuditLogger::log(AuditEntry {
                    timestamp: AuditLogger::now(),
                    session_id: self.session_id.clone(),
                    event_type: AuditEventType::Decision,
                    tool: Some(tool_name.to_string()),
                    decision: Some("ALLOWED".to_string()),
                    details: None,
                });
                
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
                 AuditLogger::log(AuditEntry {
                    timestamp: AuditLogger::now(),
                    session_id: self.session_id.clone(),
                    event_type: AuditEventType::Decision,
                    tool: Some(tool_name.to_string()),
                    decision: Some("DENIED".to_string()),
                    details: Some(serde_json::json!({"reason": reason})),
                });
                SecurityDecision::Deny {
                    error_code: jsonrpc::ERROR_SECURITY_BLOCK,
                    reason,
                }
            },
            Decision::AllowedWithSideEffects { taints_to_add, taints_to_remove } => {
                self.record_history(tool_name, classes);
                
                for t in &taints_to_add { self.taints.insert(t.clone()); }
                for t in &taints_to_remove { self.taints.remove(t); }

                let details = serde_json::json!({
                    "taints_added": taints_to_add,
                    "taints_removed": taints_to_remove
                });
                
                AuditLogger::log(AuditEntry {
                    timestamp: AuditLogger::now(),
                    session_id: self.session_id.clone(),
                    event_type: AuditEventType::Decision,
                    tool: Some(tool_name.to_string()),
                    decision: Some("ALLOWED_WITH_SIDE_EFFECTS".to_string()),
                    details: Some(details),
                });

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
            timestamp: AuditLogger::now(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::events::SecurityEvent;
    
    #[tokio::test]
    async fn test_security_core_flow() {
        let config = Arc::new(Config::default());
        let signer = CryptoSigner::new();
        let mut core = SecurityCore::new(config, signer);
        
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
    }
}
