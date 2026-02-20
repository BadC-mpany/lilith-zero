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

//! Domain models for the lilith-zero interceptor.
//!
//! This module contains pure data structures representing policies, rules,
//! tool calls, and decisions. It is designed to be free of I/O side effects.

// Domain models - Pure Rust domain logic with zero I/O dependencies

use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

/// Newtype wrapper around Uuid for type-safe session identification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionId(Uuid);

impl SessionId {
    /// Create a new SessionId from a Uuid
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// Get the underlying Uuid
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Generate a new random SessionId
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

/// Tool call representation with tool name and arguments
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool_name: String,
    pub args: serde_json::Value,
}

/// Proxy request structure matching Python ProxyRequest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequest {
    pub session_id: String,
    pub tool_name: String,
    pub args: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_callback_url: Option<String>,
}

/// Policy evaluation decision result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Decision {
    /// Request is allowed
    Allowed,
    /// Request is denied with a reason
    Denied { reason: String },
    /// Request is allowed but with side effects (taints to add/remove)
    AllowedWithSideEffects {
        taints_to_add: Vec<String>,
        taints_to_remove: Vec<String>,
    },
}

/// Recursive Logic Condition (Typed AST)
/// Replaces raw serde_json::Value with a strict enum for maintaining correctness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
// Note: standard JsonLogic often uses standard names. We support: "and", "or", "not", "==", ">", etc.
pub enum LogicCondition {
    // Logic Ops
    And(Vec<LogicCondition>),
    Or(Vec<LogicCondition>),
    Not(Box<LogicCondition>),

    // Comparison Ops
    #[serde(rename = "==")]
    Eq(Vec<LogicValue>), // [LHS, RHS]
    #[serde(rename = "!=")]
    Neq(Vec<LogicValue>),
    #[serde(rename = ">")]
    Gt(Vec<LogicValue>),
    #[serde(rename = "<")]
    Lt(Vec<LogicValue>),

    // Domain Specific
    #[serde(rename = "tool_args_match")]
    ToolArgsMatch(serde_json::Value),

    // Fallback/Extensions (or simple boolean literal)
    // Sometimes logic is just "true"
    #[serde(untagged)]
    Literal(bool),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[non_exhaustive]
pub enum LogicValue {
    /// {"var": "path"}
    Var {
        var: String,
    },
    /// Literal values
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
    /// Nested complex object (rare but supported in standard)
    Object(serde_json::Value),
    Array(Vec<serde_json::Value>),
}

/// Exception condition for rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleException {
    /// Condition that must be true for exception to apply (logic pattern format)
    #[serde(rename = "when")]
    pub condition: LogicCondition,
    /// Reason for the exception (documentation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_class: Option<String>,
    pub action: String, // ALLOW, BLOCK, ADD_TAINT, CHECK_TAINT, REMOVE_TAINT
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forbidden_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "required_taints")]
    pub required_taints: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<LogicCondition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exceptions: Option<Vec<RuleException>>,
}

/// Policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDefinition {
    pub id: String,
    pub customer_id: String,
    pub name: String,
    pub version: u32,
    /// Static rules: tool_name -> "ALLOW" or "DENY"
    #[serde(alias = "static_rules")]
    pub static_rules: std::collections::HashMap<String, String>,
    /// Dynamic taint rules
    #[serde(alias = "taint_rules")]
    pub taint_rules: Vec<PolicyRule>,
    #[serde(alias = "created_at", default)]
    pub created_at: Option<String>,
    /// Resource access rules
    #[serde(alias = "resource_rules", default)]
    pub resource_rules: Vec<ResourceRule>,
    /// Enable automatic lethal trifecta protection
    #[serde(alias = "protect_lethal_trifecta", default)]
    pub protect_lethal_trifecta: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRule {
    pub uri_pattern: String, // Glob pattern e.g. "file:///tmp/*"
    pub action: String,      // ALLOW, BLOCK
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exceptions: Option<Vec<RuleException>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "taints_to_add")]
    pub taints_to_add: Option<Vec<String>>,
}

impl PolicyRule {
    /// Check if this rule matches the given tool name and tool classes
    pub fn matches_tool(&self, tool_name: &str, tool_classes: &[String]) -> bool {
        // Match by exact tool name
        if let Some(ref rule_tool) = self.tool {
            if rule_tool == tool_name {
                return true;
            }
        }

        // Match by tool class
        if let Some(ref rule_class) = self.tool_class {
            if tool_classes.iter().any(|class| class == rule_class) {
                return true;
            }
        }

        false
    }
}

/// Customer configuration matching Python CustomerConfig structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerConfig {
    pub owner: String,
    pub mcp_upstream_url: String,
    pub policy_name: String,
}

/// History entry for session history tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub tool: String,
    pub classes: Vec<String>,
    pub timestamp: f64,
}

/// Tool configuration (schema and metadata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    #[serde(rename = "taintClass")]
    pub taint_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<serde_json::Value>,
    pub id: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<JsonRpcError>,
    pub id: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<serde_json::Value>,
}
