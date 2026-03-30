//! MCP transport layer: stdio codec, pipeline, server middleware, and process supervision.

/// Upstream subprocess lifecycle management.
pub mod process;

/// LSP-style `Content-Length` framing codec for MCP stdio transport.
pub mod codec;
/// Async reader tasks for downstream agent and upstream server I/O.
pub mod pipeline;
/// Main MCP security middleware event loop.
pub mod server;
/// macOS parent-death supervisor re-exec mode.
pub mod supervisor;
/// Tool-description pinning for rug-pull prevention.
pub mod pin_store;
