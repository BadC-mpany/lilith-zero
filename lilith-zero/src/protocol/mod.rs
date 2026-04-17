//! MCP protocol version adapters and handshake negotiation.

/// Protocol version selection based on the client's `initialize` request.
pub mod negotiation;
/// Adapter for the MCP `2024-11-05` specification revision.
pub mod v2024_11_05;
/// Adapter for the MCP `2025-11-25` / `2025-06-18` specification revisions.
pub mod v2025_11_25;
