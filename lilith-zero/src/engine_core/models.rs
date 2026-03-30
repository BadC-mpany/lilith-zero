// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

/// A strongly-typed, UUID-backed session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionId(Uuid);

impl SessionId {
    /// Wrap an existing [`Uuid`] in a [`SessionId`].
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// Borrow the inner [`Uuid`].
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Generate a new random [`SessionId`].
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
}

impl FromStr for SessionId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(SessionId)
    }
}

impl From<SessionId> for String {
    fn from(id: SessionId) -> Self {
        id.0.to_string()
    }
}

impl TryFrom<String> for SessionId {
    type Error = uuid::Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Uuid::parse_str(&s).map(SessionId)
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A single MCP tool invocation with its name and arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Name of the MCP tool being called.
    pub tool_name: String,
    /// Raw JSON arguments passed to the tool.
    pub args: serde_json::Value,
}

/// An MCP tool-call request forwarded to the upstream proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequest {
    /// The session identifier for the agent making the request.
    pub session_id: String,
    /// Name of the tool being called.
    pub tool_name: String,
    /// Raw JSON arguments for the tool call.
    pub args: serde_json::Value,
    /// Optional URL where the agent expects asynchronous results to be delivered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_callback_url: Option<String>,
}

/// The outcome returned by the policy evaluator for a single tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Decision {
    /// The tool call is permitted with no side effects.
    Allowed,
    /// The tool call is denied with an explanatory reason.
    Denied {
        /// Human-readable reason for the denial.
        reason: String,
    },
    /// The tool call is permitted but causes taint side effects on the session.
    AllowedWithSideEffects {
        /// Taint tags to add to the session.
        taints_to_add: Vec<String>,
        /// Taint tags to remove from the session.
        taints_to_remove: Vec<String>,
    },
}

/// A boolean condition expression used in policy patterns and rule exceptions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LogicCondition {
    /// All child conditions must be true.
    And(Vec<LogicCondition>),
    /// At least one child condition must be true.
    Or(Vec<LogicCondition>),
    /// The child condition must be false.
    Not(Box<LogicCondition>),

    /// Equality comparison between two [`LogicValue`]s.
    #[serde(rename = "==")]
    Eq(Vec<LogicValue>), // [LHS, RHS]
    /// Inequality comparison between two [`LogicValue`]s.
    #[serde(rename = "!=")]
    Neq(Vec<LogicValue>),
    /// Greater-than comparison between two [`LogicValue`]s.
    #[serde(rename = ">")]
    Gt(Vec<LogicValue>),
    /// Less-than comparison between two [`LogicValue`]s.
    #[serde(rename = "<")]
    Lt(Vec<LogicValue>),

    /// Matches tool arguments against a JSON object spec (supports wildcard strings).
    #[serde(rename = "tool_args_match")]
    ToolArgsMatch(serde_json::Value),

    /// A constant boolean literal.
    #[serde(untagged)]
    Literal(bool),
}

/// A value operand in a [`LogicCondition`] expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[non_exhaustive]
pub enum LogicValue {
    /// A reference to a named tool argument resolved at evaluation time.
    Var {
        /// Name of the tool argument to resolve.
        var: String,
    },
    /// A string literal.
    Str(String),
    /// A numeric literal.
    Num(f64),
    /// A boolean literal.
    Bool(bool),
    /// A JSON null literal.
    Null,
    /// An arbitrary JSON object literal.
    Object(serde_json::Value),
    /// An arbitrary JSON array literal.
    Array(Vec<serde_json::Value>),
}

/// A conditional exception to a taint or block rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleException {
    /// The condition that, when true, causes the parent rule to be skipped.
    #[serde(rename = "when")]
    pub condition: LogicCondition,
    /// Optional human-readable explanation for why this exception exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A single taint or block rule within a [`PolicyDefinition`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRule {
    /// Exact tool name this rule applies to (mutually exclusive with `tool_class`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Tool class this rule applies to (mutually exclusive with `tool`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_class: Option<String>,
    /// Action to take: `ALLOW`, `BLOCK`, `ADD_TAINT`, `CHECK_TAINT`, or `REMOVE_TAINT`.
    pub action: String,
    /// Taint tag to add or remove (required for `ADD_TAINT` / `REMOVE_TAINT`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Taint tags that, if any are present, cause a `CHECK_TAINT` rule to block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forbidden_tags: Option<Vec<String>>,
    /// Taint tags that, if ALL are present simultaneously, cause a `CHECK_TAINT` rule to block.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "required_taints")]
    pub required_taints: Option<Vec<String>>,
    /// Custom error message returned to the agent when this rule fires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Optional logic pattern that must match for the rule to apply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<LogicCondition>,
    /// Conditions under which this rule is skipped even if it would otherwise fire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exceptions: Option<Vec<RuleException>>,
}

/// A complete security policy, including static allow/deny rules, taint rules, and resource rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDefinition {
    /// Unique identifier for this policy.
    pub id: String,
    /// Customer or tenant this policy belongs to.
    pub customer_id: String,
    /// Human-readable name for this policy.
    pub name: String,
    /// Schema version number; increment on breaking changes.
    pub version: u32,
    /// Static per-tool rules mapping tool name → `"ALLOW"` or `"DENY"`.
    #[serde(alias = "static_rules")]
    pub static_rules: std::collections::HashMap<String, String>,
    /// Ordered list of taint/block rules evaluated for each tool call.
    #[serde(alias = "taint_rules")]
    pub taint_rules: Vec<PolicyRule>,
    /// ISO 8601 creation timestamp (informational).
    #[serde(alias = "created_at", default)]
    pub created_at: Option<String>,
    /// Rules governing access to MCP resources (URIs).
    #[serde(alias = "resource_rules", default)]
    pub resource_rules: Vec<ResourceRule>,
    /// When `true`, auto-inject the lethal-trifecta EXFILTRATION protection rule.
    #[serde(alias = "protect_lethal_trifecta", default)]
    pub protect_lethal_trifecta: bool,
}

/// A rule governing access to MCP resources identified by URI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRule {
    /// Glob-style URI pattern (e.g. `"file:///tmp/*"`).
    pub uri_pattern: String,
    /// Action to take: `"ALLOW"` or `"BLOCK"`.
    pub action: String,
    /// Conditions under which this rule is skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exceptions: Option<Vec<RuleException>>,
    /// Taint tags to add to the session when this rule fires.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "taints_to_add")]
    pub taints_to_add: Option<Vec<String>>,
}

impl PolicyRule {
    /// Returns `true` if this rule targets `tool_name` directly or via one of its `tool_classes`.
    pub fn matches_tool(&self, tool_name: &str, tool_classes: &[String]) -> bool {
        if let Some(ref rule_tool) = self.tool {
            if rule_tool == tool_name {
                return true;
            }
        }

        if let Some(ref rule_class) = self.tool_class {
            if tool_classes.iter().any(|class| class == rule_class) {
                return true;
            }
        }

        false
    }
}

/// Per-customer configuration for the MCP upstream proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerConfig {
    /// Owner identifier.
    pub owner: String,
    /// URL of the upstream MCP server.
    pub mcp_upstream_url: String,
    /// Name of the security policy to apply for this customer.
    pub policy_name: String,
}

/// A single entry in the per-session tool-call history used for sequential pattern matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Name of the tool that was called.
    pub tool: String,
    /// Classes assigned to the tool at the time of the call.
    pub classes: Vec<String>,
    /// Unix timestamp (seconds since epoch) of the call.
    pub timestamp: f64,
}

/// Metadata describing a single MCP tool as advertised by the upstream server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    /// Tool name as registered with the MCP server.
    pub name: String,
    /// Human-readable description of the tool's behaviour.
    pub description: String,
    /// JSON Schema for the tool's input parameters.
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
    /// Severity classification used for audit logging (e.g. `"high"`, `"low"`).
    #[serde(default)]
    pub severity: String,
    /// Optional taint class assigned to this tool (e.g. `"EXFILTRATION"`).
    #[serde(default)]
    #[serde(rename = "taintClass")]
    pub taint_class: Option<String>,
}

/// A JSON-RPC 2.0 request message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// The JSON-RPC method name.
    pub method: String,
    /// Optional method parameters.
    pub params: Option<serde_json::Value>,
    /// Request identifier; `None` for notifications.
    pub id: Option<serde_json::Value>,
}

/// A JSON-RPC 2.0 response message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// The result value, present on success.
    pub result: Option<serde_json::Value>,
    /// The error object, present on failure.
    pub error: Option<JsonRpcError>,
    /// The identifier from the matching request.
    pub id: serde_json::Value,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Numeric error code.
    pub code: i32,
    /// Short, human-readable error message.
    pub message: String,
    /// Optional additional error data.
    pub data: Option<serde_json::Value>,
}
