//! Protocol-agnostic security events and decision types.
//!
//! This module defines the internal event stream that the Security Core operates on.
//! It is completely decoupled from the specific MCP wire protocol version.

use crate::core::taint::Tainted;
use crate::core::types::TaintedString;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Protocol-agnostic security events derived from wire protocol messages
#[derive(Debug, Clone)]
pub enum SecurityEvent {
    /// Session initialization (e.g. MCP "initialize")
    Handshake {
        protocol_version: String,
        client_info: Value,
        /// Optional authentication token (OAuth or similar)
        audience_token: Option<String>,
        /// Capabilities offered by the client
        capabilities: Value,
    },
    /// A generic request to execute an action (tool call)
    ToolRequest {
        /// Request ID for correlation (opaque)
        request_id: Value,
        /// Name of the tool being called
        tool_name: TaintedString,
        /// Arguments provided to the tool
        arguments: Tainted<Value>,
        /// Session token for validation
        session_token: Option<String>,
    },
    /// A request to read/access a resource
    ResourceRequest {
        request_id: Value,
        /// URI of the resource
        uri: TaintedString,
        session_token: Option<String>,
    },
    /// A generic passthrough event (notifications, pings, or method-not-found)
    /// These are typically allowed by default but logged.
    Passthrough {
        request_id: Option<Value>,
        method: String,
        params: Option<Value>,
    },
}

/// The authoritative decision from the Security Core
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityDecision {
    /// Proceed with the operation as-is
    Allow,
    /// Proceed, but apply transformations to the result (Active Defense)
    AllowWithTransforms {
        taints_to_add: Vec<String>,
        taints_to_remove: Vec<String>,
        output_transforms: Vec<OutputTransform>,
    },
    /// Block the operation
    Deny {
        /// JSON-RPC compatible error code
        error_code: i32,
        /// Human-readable reason
        reason: String,
    },
}

/// Instructions for transforming the upstream response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputTransform {
    /// Apply spotlighting (randomized XML tags) to specific JSON paths
    Spotlight {
        /// JSONPaths to fields that should be spotlighted (e.g., "content[*].text")
        json_paths: Vec<String>,
    },
    /// Redact specific fields (Data Loss Prevention)
    Redact { json_paths: Vec<String> },
}
