//! Core engine primitives: errors, events, models, crypto, taint, session, and traits.

/// HMAC-signed audit logging.
pub mod audit;
/// JWT audience claim validation.
pub mod auth;
/// Compile-time string constants for JSON-RPC codes, env vars, spotlighting, etc.
pub mod constants;
/// HMAC-SHA256 session ID generation and validation.
pub mod crypto;
/// Error types for all middleware operations.
pub mod errors;
/// Security event and decision types produced by the protocol adapters.
pub mod events;
/// Data models: policies, rules, JSON-RPC messages, and session structures.
pub mod models;
/// State persistence for ephemeral hook execution.
pub mod persistence;
/// Per-session security state and policy evaluation entry point.
pub mod security_core;
/// Active protocol-version adapter for the current MCP session.
pub mod session;
/// Compile-time taint wrappers (`Tainted<T>` / `Clean<T>`).
pub mod taint;
/// Zero-dependency telemetry integration hook trait.
pub mod telemetry;
/// `McpSessionHandler` trait implemented by each protocol adapter.
pub mod traits;
/// `TaintedString` and `SafeString` newtypes.
pub mod types;
