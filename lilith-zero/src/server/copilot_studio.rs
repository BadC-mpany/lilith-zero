// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

//! Copilot Studio webhook request / response types and payload mapping.
//!
//! Implements the REST API defined at:
//! <https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers>
//!
//! # Endpoints
//! - `POST /validate` — health check, returns [`ValidationResponse`].
//! - `POST /analyze-tool-execution` — evaluates tool execution, returns [`AnalyzeToolExecutionResponse`].
//!
//! # Mapping to the security engine
//! [`AnalyzeToolExecutionRequest`] maps to the internal [`HookInput`] as follows:
//!
//! | Copilot Studio field                   | Internal field        |
//! |----------------------------------------|-----------------------|
//! | `conversationMetadata.conversationId`  | `session_id`          |
//! | `toolDefinition.name`                  | `tool_name`           |
//! | `inputValues`                          | `tool_input`          |
//! | (fixed)                                | `hook_event_name = "PreToolUse"` |

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// /validate endpoint
// ---------------------------------------------------------------------------

/// Response for `POST /validate`.
///
/// Copilot Studio calls this endpoint during configuration to verify the
/// webhook is reachable. Return HTTP 200 with this body on success.
#[derive(Debug, Serialize, Clone)]
pub struct ValidationResponse {
    /// Indicates whether the validation passed.
    #[serde(rename = "isSuccessful")]
    pub is_successful: bool,
    /// Human-readable status description.
    pub status: String,
}

impl ValidationResponse {
    /// Construct a successful validation response.
    pub fn ok() -> Self {
        Self {
            is_successful: true,
            status: "OK".to_string(),
        }
    }

    /// Construct a failed validation response with a descriptive status.
    pub fn not_ready(status: impl Into<String>) -> Self {
        Self {
            is_successful: false,
            status: status.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// /analyze-tool-execution endpoint — request
// ---------------------------------------------------------------------------

/// Full request body for `POST /analyze-tool-execution`.
#[derive(Debug, Deserialize, Clone)]
pub struct AnalyzeToolExecutionRequest {
    /// Context about the planner's reasoning leading up to this tool call.
    #[serde(rename = "plannerContext")]
    pub planner_context: PlannerContext,

    /// Metadata describing the tool to be invoked.
    #[serde(rename = "toolDefinition")]
    pub tool_definition: ToolDefinition,

    /// Actual argument values passed to the tool (key-value map).
    #[serde(rename = "inputValues")]
    pub input_values: serde_json::Value,

    /// Metadata about the conversation, agent, and user.
    #[serde(rename = "conversationMetadata")]
    pub conversation_metadata: ConversationMetadata,
}

/// Planner context delivered with each tool execution request.
#[derive(Debug, Deserialize, Clone)]
pub struct PlannerContext {
    /// The original user message that triggered this plan.
    #[serde(rename = "userMessage")]
    pub user_message: String,

    /// Planner's explanation for why this tool was selected.
    #[serde(default)]
    pub thought: Option<String>,

    /// Recent conversation history.
    #[serde(rename = "chatHistory", default)]
    pub chat_history: Option<Vec<ChatMessage>>,

    /// Outputs from previously executed tools in this plan step.
    #[serde(rename = "previousToolOutputs", default)]
    pub previous_tool_outputs: Option<Vec<ToolExecutionOutput>>,
}

/// A single message in the conversation history.
#[derive(Debug, Deserialize, Clone)]
pub struct ChatMessage {
    /// Unique identifier for this message.
    pub id: String,
    /// Source of the message: `"user"` or `"assistant"`.
    pub role: String,
    /// Message text.
    pub content: String,
    /// ISO 8601 timestamp.
    #[serde(default)]
    pub timestamp: Option<String>,
}

/// A tool's output from a previous plan step.
#[derive(Debug, Deserialize, Clone)]
pub struct ToolExecutionOutput {
    /// Unique tool identifier.
    #[serde(rename = "toolId")]
    pub tool_id: String,
    /// Tool name.
    #[serde(rename = "toolName")]
    pub tool_name: String,
    /// The tool's output values.
    pub outputs: serde_json::Value,
    /// ISO 8601 timestamp of completion.
    #[serde(default)]
    pub timestamp: Option<String>,
}

/// Metadata describing the tool to be invoked.
#[derive(Debug, Deserialize, Clone)]
pub struct ToolDefinition {
    /// Unique tool identifier within Copilot Studio.
    pub id: String,
    /// Tool kind: `"PrebuiltToolDefinition"`, `"CustomToolDefinition"`, etc.
    #[serde(rename = "type")]
    pub tool_type: String,
    /// Human-readable tool name — used as the policy key for evaluation.
    pub name: String,
    /// Summary of what the tool does.
    pub description: String,
    /// Declared input parameters (schema, not actual values).
    #[serde(rename = "inputParameters", default)]
    pub input_parameters: Option<Vec<ToolParameter>>,
    /// Declared output parameters.
    #[serde(rename = "outputParameters", default)]
    pub output_parameters: Option<Vec<ToolParameter>>,
}

/// A single parameter in a tool's signature.
#[derive(Debug, Deserialize, Clone)]
pub struct ToolParameter {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "type", default)]
    pub param_type: Option<serde_json::Value>,
}

/// Metadata about the ongoing conversation and its agent / user context.
#[derive(Debug, Deserialize, Clone)]
pub struct ConversationMetadata {
    /// Agent information (id, tenant, environment).
    pub agent: AgentContext,
    /// User information.
    #[serde(default)]
    pub user: Option<UserContext>,
    /// Trigger that started this plan.
    #[serde(default)]
    pub trigger: Option<TriggerContext>,
    /// The stable conversation identifier — used as the Lilith session ID.
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    /// Plan identifier.
    #[serde(rename = "planId", default)]
    pub plan_id: Option<String>,
    /// Step within the plan.
    #[serde(rename = "planStepId", default)]
    pub plan_step_id: Option<String>,
}

/// Agent-level context within a conversation.
#[derive(Debug, Deserialize, Clone)]
pub struct AgentContext {
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "environmentId")]
    pub environment_id: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(rename = "isPublished")]
    pub is_published: bool,
}

/// User-level context within a conversation.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct UserContext {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "tenantId", default)]
    pub tenant_id: Option<String>,
}

/// Trigger context within a conversation.
#[derive(Debug, Deserialize, Clone)]
pub struct TriggerContext {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "schemaName", default)]
    pub schema_name: Option<String>,
}

// ---------------------------------------------------------------------------
// /analyze-tool-execution endpoint — response
// ---------------------------------------------------------------------------

/// Allow/block response for `POST /analyze-tool-execution`.
#[derive(Debug, Serialize, Clone)]
pub struct AnalyzeToolExecutionResponse {
    /// `true` to block the tool invocation; `false` to allow it.
    #[serde(rename = "blockAction")]
    pub block_action: bool,

    /// Partner-defined numeric reason code for the block.
    #[serde(rename = "reasonCode", skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<i32>,

    /// Human-readable explanation shown in Copilot Studio logs.
    #[serde(rename = "reason", skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Freeform diagnostic info (pre-serialized string).
    #[serde(rename = "diagnostics", skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<String>,
}

impl AnalyzeToolExecutionResponse {
    /// Construct an allow response.
    pub fn allow() -> Self {
        Self {
            block_action: false,
            reason_code: None,
            reason: None,
            diagnostics: None,
        }
    }

    /// Construct a block response with a reason code and message.
    pub fn block(reason_code: i32, reason: impl Into<String>) -> Self {
        Self {
            block_action: true,
            reason_code: Some(reason_code),
            reason: Some(reason.into()),
            diagnostics: None,
        }
    }
}

/// Reason codes for block decisions (partner-defined per MS spec).
pub mod reason_codes {
    /// No security policy is loaded; fail-closed default deny.
    pub const NO_POLICY: i32 = 1001;
    /// Tool is explicitly listed as DENY in the static rules.
    pub const STATIC_DENY: i32 = 1002;
    /// Tool is blocked because an active taint rule triggered.
    pub const TAINT_BLOCK: i32 = 1003;
    /// Tool is not found in the policy; denied by fail-closed default.
    pub const UNKNOWN_TOOL: i32 = 1004;
    /// Internal policy evaluation error; fail-closed.
    pub const EVAL_ERROR: i32 = 1005;
}

// ---------------------------------------------------------------------------
// Error response (used for HTTP 4xx / 5xx)
// ---------------------------------------------------------------------------

/// Error response body returned on HTTP 400 / 401 / 500.
#[derive(Debug, Serialize, Clone)]
pub struct WebhookErrorResponse {
    /// Numeric error code.
    #[serde(rename = "errorCode")]
    pub error_code: i32,
    /// Human-readable explanation.
    pub message: String,
    /// HTTP status code repeated in the body for client convenience.
    #[serde(rename = "httpStatus")]
    pub http_status: u16,
    /// Optional freeform diagnostics.
    #[serde(rename = "diagnostics", skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<String>,
}

impl WebhookErrorResponse {
    pub fn new(error_code: i32, message: impl Into<String>, http_status: u16) -> Self {
        Self {
            error_code,
            message: message.into(),
            http_status,
            diagnostics: None,
        }
    }
}

/// Error codes for webhook-level errors (auth, parsing).
pub mod error_codes {
    pub const MISSING_AUTH: i32 = 2001;
    pub const INVALID_JWT_FORMAT: i32 = 2002;
    pub const JWT_VALIDATION_FAILED: i32 = 2003;
    pub const MISSING_REQUIRED_FIELD: i32 = 4001;
    pub const INTERNAL_ERROR: i32 = 5001;
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

/// Map a Copilot Studio request to the internal [`crate::hook::HookInput`] format.
///
/// The `conversationId` becomes the session ID, enabling taint state to persist
/// across multiple tool invocations within the same Copilot Studio conversation.
pub fn to_hook_input(req: &AnalyzeToolExecutionRequest) -> crate::hook::HookInput {
    crate::hook::HookInput {
        session_id: req.conversation_metadata.conversation_id.clone(),
        hook_event_name: "PreToolUse".to_string(),
        tool_name: Some(req.tool_definition.id.clone()),
        tool_input: Some(req.input_values.clone()),
        tool_output: None,
        request_id: None,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_REQUEST: &str = r#"{
        "plannerContext": {
            "userMessage": "Send an email"
        },
        "toolDefinition": {
            "id": "tool-1",
            "type": "PrebuiltToolDefinition",
            "name": "send_email",
            "description": "Sends an email"
        },
        "inputValues": {
            "to": "user@example.com"
        },
        "conversationMetadata": {
            "agent": {
                "id": "agent-1",
                "tenantId": "tenant-1",
                "environmentId": "env-1",
                "isPublished": true
            },
            "conversationId": "conv-abc-123"
        }
    }"#;

    const FULL_REQUEST: &str = r#"{
        "plannerContext": {
            "userMessage": "Send an email to the customer",
            "thought": "User wants to notify customer",
            "chatHistory": [
                {"id": "m1", "role": "user", "content": "Send email", "timestamp": "2025-05-25T08:00:00Z"}
            ],
            "previousToolOutputs": [
                {
                    "toolId": "tool-0",
                    "toolName": "get_email",
                    "outputs": {"email": "user@example.com"},
                    "timestamp": "2025-05-25T08:00:01Z"
                }
            ]
        },
        "toolDefinition": {
            "id": "tool-1",
            "type": "PrebuiltToolDefinition",
            "name": "send_email",
            "description": "Sends an email",
            "inputParameters": [
                {"name": "to", "description": "Recipient"},
                {"name": "bcc", "description": "BCC"}
            ],
            "outputParameters": [
                {"name": "result", "description": "Outcome"}
            ]
        },
        "inputValues": {
            "to": "customer@foobar.com",
            "bcc": "hacker@evil.com"
        },
        "conversationMetadata": {
            "agent": {
                "id": "agent-guid",
                "tenantId": "tenant-guid",
                "environmentId": "env-guid",
                "isPublished": true
            },
            "user": {"id": "user-guid", "tenantId": "tenant-guid"},
            "trigger": {"id": "trigger-guid", "schemaName": "trigger-schema"},
            "conversationId": "conv-id",
            "planId": "plan-guid",
            "planStepId": "step-1"
        }
    }"#;

    #[test]
    fn test_minimal_request_deserializes() {
        let req: AnalyzeToolExecutionRequest =
            serde_json::from_str(MINIMAL_REQUEST).expect("minimal request must deserialize");
        assert_eq!(req.tool_definition.name, "send_email");
        assert_eq!(req.conversation_metadata.conversation_id, "conv-abc-123");
    }

    #[test]
    fn test_full_request_deserializes() {
        let req: AnalyzeToolExecutionRequest =
            serde_json::from_str(FULL_REQUEST).expect("full request must deserialize");
        assert_eq!(
            req.planner_context.user_message,
            "Send an email to the customer"
        );
        let history = req.planner_context.chat_history.as_ref().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].role, "user");
        assert_eq!(req.input_values["bcc"].as_str(), Some("hacker@evil.com"));
    }

    #[test]
    fn test_to_hook_input_maps_conversation_id_to_session_id() {
        let req: AnalyzeToolExecutionRequest = serde_json::from_str(MINIMAL_REQUEST).unwrap();
        let hook = to_hook_input(&req);
        assert_eq!(hook.session_id, "conv-abc-123");
    }

    #[test]
    fn test_to_hook_input_maps_tool_name() {
        let req: AnalyzeToolExecutionRequest = serde_json::from_str(MINIMAL_REQUEST).unwrap();
        let hook = to_hook_input(&req);
        assert_eq!(hook.tool_name.as_deref(), Some("tool-1"));
    }

    #[test]
    fn test_to_hook_input_event_is_pre_tool_use() {
        let req: AnalyzeToolExecutionRequest = serde_json::from_str(MINIMAL_REQUEST).unwrap();
        let hook = to_hook_input(&req);
        assert_eq!(hook.hook_event_name, "PreToolUse");
    }

    #[test]
    fn test_to_hook_input_maps_input_values_as_tool_input() {
        let req: AnalyzeToolExecutionRequest = serde_json::from_str(FULL_REQUEST).unwrap();
        let hook = to_hook_input(&req);
        let input = hook.tool_input.expect("tool_input must be set");
        assert_eq!(input["to"].as_str(), Some("customer@foobar.com"));
        assert_eq!(input["bcc"].as_str(), Some("hacker@evil.com"));
    }

    #[test]
    fn test_validation_response_ok_format() {
        let r = ValidationResponse::ok();
        assert!(r.is_successful);
        assert_eq!(r.status, "OK");
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("isSuccessful"));
        assert!(json.contains("true"));
    }

    #[test]
    fn test_analyze_response_allow_no_extra_fields() {
        let r = AnalyzeToolExecutionResponse::allow();
        assert!(!r.block_action);
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("reasonCode"),
            "allow must not include reasonCode"
        );
        assert!(!json.contains("reason"), "allow must not include reason");
    }

    #[test]
    fn test_analyze_response_block_includes_reason() {
        let r = AnalyzeToolExecutionResponse::block(reason_codes::STATIC_DENY, "denied by policy");
        assert!(r.block_action);
        assert_eq!(r.reason_code, Some(1002));
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("blockAction"));
        assert!(json.contains("reasonCode"));
        assert!(json.contains("reason"));
    }

    #[test]
    fn test_error_response_serializes_correctly() {
        let e = WebhookErrorResponse::new(error_codes::MISSING_AUTH, "unauthorized", 401);
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("errorCode"));
        assert!(json.contains("httpStatus"));
        assert!(json.contains("401"));
    }
}
