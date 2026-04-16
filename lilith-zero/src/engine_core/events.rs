// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::engine_core::taint::Tainted;
use crate::engine_core::types::TaintedString;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// An MCP request parsed and classified by the protocol adapter for security evaluation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SecurityEvent {
    /// MCP `initialize` handshake from the downstream agent.
    Handshake {
        /// The MCP protocol version string the client is requesting.
        protocol_version: String,
        /// Client metadata from the `clientInfo` field.
        client_info: Value,
        /// Optional JWT audience token for authentication.
        audience_token: Option<String>,
        /// Client-declared capability flags.
        capabilities: Value,
    },
    /// An MCP `tools/call` invocation to be evaluated against taint policy.
    ToolRequest {
        /// The JSON-RPC request identifier, used to correlate responses.
        request_id: Value,
        /// The tool name, treated as tainted until policy evaluation clears it.
        tool_name: TaintedString,
        /// The tool arguments, wrapped in taint metadata.
        arguments: Tainted<Value>,
        /// Optional session token included in the request parameters.
        session_token: Option<String>,
    },
    /// An MCP `resources/read` call to be evaluated against resource rules.
    ResourceRequest {
        /// The JSON-RPC request identifier.
        request_id: Value,
        /// The resource URI, treated as tainted.
        uri: TaintedString,
        /// Optional session token included in the request parameters.
        session_token: Option<String>,
    },
    /// A request that requires no security evaluation and is forwarded as-is.
    Passthrough {
        /// The JSON-RPC request identifier, if present.
        request_id: Option<Value>,
        /// The JSON-RPC method name.
        method: String,
        /// The raw request parameters.
        params: Option<Value>,
    },
}

/// The outcome of evaluating a [`SecurityEvent`] against the loaded policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SecurityDecision {
    /// The request is permitted without modification.
    Allow,
    /// The request is permitted with side-effects and/or output transforms applied.
    AllowWithTransforms {
        /// Taint tags to add to the session after this request is processed.
        taints_to_add: Vec<String>,
        /// Taint tags to remove from the session after this request is processed.
        taints_to_remove: Vec<String>,
        /// Output transforms to apply to the upstream response before forwarding.
        output_transforms: Vec<OutputTransform>,
    },
    /// The request is blocked by policy.
    Deny {
        /// JSON-RPC error code to return to the client.
        error_code: i32,
        /// Human-readable reason for the denial (may be forwarded to the agent).
        reason: String,
    },
}

/// A transformation applied to tool-response content before it is forwarded to the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OutputTransform {
    /// Redact content at the specified JSON paths.
    Redact {
        /// JSON paths within the response to redact.
        json_paths: Vec<String>,
    },
}
