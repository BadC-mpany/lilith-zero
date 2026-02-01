//! Protocol Session Handler Trait.
//!
//! Defines the interface for converting between specific wire protocols
//! and the internal SecurityEvent model.

use crate::core::events::{SecurityEvent, SecurityDecision};
use crate::protocol::types::{JsonRpcRequest, JsonRpcResponse};

/// Handler to translate between generic SecurityEvents and specific wire protocol versions.
pub trait McpSessionHandler: Send + Sync {
    /// Returns the protocol version string supported by this handler
    fn version(&self) -> &'static str;

    /// Parse a raw JSON-RPC request into a generic SecurityEvent.
    fn parse_request(&self, req: &JsonRpcRequest) -> SecurityEvent;

    /// Apply the security decision to the upstream response.
    fn apply_decision(
        &self,
        decision: &SecurityDecision,
        response: JsonRpcResponse,
    ) -> JsonRpcResponse;

    /// Extract the session token from the request headers or parameters.
    fn extract_session_token(&self, req: &JsonRpcRequest) -> Option<String>;
    
    /// Prepare the request for forwarding to the upstream server.
    fn sanitize_for_upstream(&self, req: &mut JsonRpcRequest);
}
