//! MCP transport layer: stdio codec, pipeline, server middleware, and process supervision.

/// Upstream subprocess lifecycle management.
pub mod process;

/// HTTP upstream transport for MCP Streamable HTTP protocol (2025-11-25).
pub mod http_upstream;

/// LSP-style `Content-Length` framing codec for MCP stdio transport.
pub mod codec;
/// Tool-description pinning for rug-pull prevention.
pub mod pin_store;
/// Async reader tasks for downstream agent and upstream server I/O.
pub mod pipeline;
/// Main MCP security middleware event loop.
pub mod server;
/// macOS parent-death supervisor re-exec mode.
pub mod supervisor;
