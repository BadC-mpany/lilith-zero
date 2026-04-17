// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0

//! Telemetry integration hook trait.
//!
//! Defines a zero-dependency plugin interface for distributed tracing.
//! Implement [`TelemetryHook`] in an external crate (e.g. `lilith-telemetry`)
//! and register it at startup via [`crate::mcp::server::McpMiddleware::with_telemetry`].
//!
//! All methods have no-op defaults — implement only what you need.
//!
//! # Example
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use lilith_zero::TelemetryHook;
//! use lilith_zero::mcp::server::McpMiddleware;
//!
//! struct MyHook;
//!
//! impl TelemetryHook for MyHook {
//!     fn on_session_start(&self, session_id: &str) {
//!         println!("Session started: {session_id}");
//!     }
//!
//!     fn on_tool_decision(&self, _session_id: &str, tool: &str, allowed: bool, reason: Option<&str>) {
//!         println!("{tool}: {}", if allowed { "ALLOW" } else { "DENY" });
//!         if let Some(r) = reason { println!("  reason: {r}"); }
//!     }
//! }
//!
//! let middleware = McpMiddleware::new(/* ... */)?.with_telemetry(Arc::new(MyHook));
//! ```

use serde_json::Value;

/// A telemetry integration hook for distributed tracing.
///
/// Implement this trait to connect `lilith-zero` to any tracing backend
/// without introducing a compile-time dependency on it.  The middleware
/// holds an `Option<Arc<dyn TelemetryHook>>` and calls these methods at
/// each instrumentation point.  All methods are optional (no-op by default).
pub trait TelemetryHook: Send + Sync + 'static {
    // ── Session ───────────────────────────────────────────────────────────

    /// Called once when an MCP session handshake completes successfully.
    fn on_session_start(&self, session_id: &str) {
        let _ = session_id;
    }

    // ── Tool evaluation ───────────────────────────────────────────────────

    /// Called when tool-request evaluation begins.
    ///
    /// Returns an opaque span guard — drop it to end the span.  Bind the
    /// return value with `let _guard = hook.begin_tool_evaluation(...)` so
    /// it lives for the duration of the evaluation scope.
    fn begin_tool_evaluation(
        &self,
        session_id: &str,
        tool_name: &str,
    ) -> Box<dyn std::any::Any + Send> {
        let _ = (session_id, tool_name);
        Box::new(())
    }

    /// Called after the policy decision for a tool request.
    ///
    /// `allowed` is `true` for ALLOW decisions, `false` for DENY.
    /// `reason` carries the denial reason when `allowed` is `false`.
    fn on_tool_decision(
        &self,
        session_id: &str,
        tool_name: &str,
        allowed: bool,
        reason: Option<&str>,
    ) {
        let _ = (session_id, tool_name, allowed, reason);
    }

    /// Called when the policy evaluator returns an internal error.
    ///
    /// The tool is denied (fail-closed) when this fires.
    fn on_policy_error(&self, session_id: &str, tool_name: &str, error: &str) {
        let _ = (session_id, tool_name, error);
    }

    // ── MCP request / response lifecycle ─────────────────────────────────

    /// Called when an MCP request arrives from the downstream agent.
    ///
    /// `params` is `Some` when the JSON-RPC message contains a `params`
    /// object — use it to extract W3C `traceparent` or custom trace fields
    /// (e.g. `_lilith_trace_id_hi`, `_lilith_trace_id_lo`, `_lilith_parent_span_id`).
    ///
    /// Returns an opaque span guard — drop it to end the span.
    fn begin_mcp_request(
        &self,
        method: &str,
        params: Option<&Value>,
    ) -> Box<dyn std::any::Any + Send> {
        let _ = (method, params);
        Box::new(())
    }

    /// Called just before a request is forwarded to the upstream MCP server.
    fn on_forward_upstream(&self, method: &str) {
        let _ = method;
    }

    /// Called when an upstream response is being processed.
    ///
    /// Returns an opaque span guard — drop it to end the span.
    fn begin_mcp_response(&self) -> Box<dyn std::any::Any + Send> {
        Box::new(())
    }

    /// Called just before a response is forwarded to the downstream client.
    fn on_forward_client(&self) {}
}
