//! Protocol Adapter Trait.
//!
//! This trait defines the interface for converting between the specific wire protocol
//! (JSON-RPC 2.0 with specific method names/versions) and the internal `SecurityEvent` model.

use crate::core::events::{SecurityEvent, SecurityDecision};
use crate::mcp::transport::{JsonRpcRequest, JsonRpcResponse};

/// Adapter to translate between generic SecurityEvents and specific wire protocol versions.
pub trait ProtocolAdapter: Send + Sync {
    /// Returns the protocol version string supported by this adapter
    fn version(&self) -> &'static str;

    /// Parse a raw JSON-RPC request into a generic SecurityEvent.
    /// This abstracts away the specific method names (e.g. "tools/call" vs future "tools/execute").
    fn parse_request(&self, req: &JsonRpcRequest) -> SecurityEvent;

    /// Apply the security decision to the upstream response.
    /// This is where output transformations (spotlighting, redaction) happen.
    /// It consumes the original response and returns a modified one.
    fn apply_decision(
        &self,
        decision: &SecurityDecision,
        response: JsonRpcResponse,
    ) -> JsonRpcResponse;

    /// Extract the session token from the request headers or parameters.
    fn extract_session_token(&self, req: &JsonRpcRequest) -> Option<String>;
    
    /// Prepare the request for forwarding to the upstream server.
    /// This typically involves stripping Sentinel-specific metadata (like session tokens)
    /// effectively "cleaning" the request so the upstream tool doesn't see our internal data.
    fn sanitize_for_upstream(&self, req: &mut JsonRpcRequest);
}
