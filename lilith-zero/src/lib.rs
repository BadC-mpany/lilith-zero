//! `lilith-zero` — MCP security middleware for AI agents.
//!
//! Provides taint-tracking, policy enforcement, session validation,
//! and lethal-trifecta protection as a transparent stdio proxy
//! between an AI agent and an MCP tool server.

#![deny(clippy::correctness)]
#![warn(clippy::suspicious)]
#![warn(clippy::style)]
#![warn(clippy::complexity)]
#![warn(clippy::perf)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub use engine_core::telemetry::TelemetryHook;

/// Runtime configuration types and security-level definitions.
pub mod config;
/// Policy evaluation engine: pattern matching and taint-rule evaluation.
pub mod engine;
/// Core engine primitives: errors, events, models, crypto, taint, session, and traits.
pub mod engine_core;
/// Claude Code hook integration.
pub mod hook;
/// MCP transport layer: stdio codec, pipeline, server middleware, and process supervision.
pub mod mcp;
/// MCP protocol version adapters and handshake negotiation.
pub mod protocol;
/// Utility helpers: policy validation, spotlighting, PE parsing, uv runtime, time.
pub mod utils;

/// Kani formal verification proofs and integration tests for core security invariants.
#[cfg(any(test, kani))]
pub mod verification;
