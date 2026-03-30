
//! # Lilith Telemetry Framework
//!
//! A high-performance, lock-free, and encrypted telemetry subsystem
//! operating as the kernel-level audit trail for Lilith-Zero deployments.

pub mod api;
pub mod baggage;
pub mod clock;
pub mod crypto;
pub mod discovery;
pub mod dispatcher;
pub mod exporter;
pub mod macros;
pub mod sampling;
pub mod scrubber;
pub mod storage;

pub use baggage::{Baggage, SessionId, SpanId, SpanKind, TraceId, SpanGuard};
pub use discovery::FlockLink;
pub use api::KeyRegistry;

use crypto::KeyHandle;
use dispatcher::Dispatcher;
use std::sync::{Arc, OnceLock};

/// Deployment role — maps to Jaeger architectural roles.
pub enum DeploymentMode {
    /// Local only. No networking. Data stays on this machine.
    Alone,
    /// Jaeger Agent equivalent. Streams encrypted traces to a FlockHead.
    FlockMember {
        target_api_endpoint: String,
        auth_key: KeyHandle,
    },
    /// Jaeger Collector+Ingester equivalent. Receives and stores traces from FlockMembers.
    FlockHead {
        bind_address: String,
        registry: Arc<KeyRegistry>,
    },
}

/// Global singleton dispatcher.
pub static DISPATCHER: OnceLock<Dispatcher> = OnceLock::new();

/// Initialize the telemetry subsystem. Call exactly once at application startup.
pub fn init(mode: DeploymentMode) {
    // If this is the head, start the background ingestion listener before the dispatcher is set.
    if let DeploymentMode::FlockHead { bind_address, registry } = &mode {
        crate::api::spawn_ingester(bind_address.clone(), registry.clone());
    }

    // Extract the node's own key ID before mode is consumed by Dispatcher::new.
    let member_key_id = match &mode {
        DeploymentMode::FlockMember { auth_key, .. } => Some(auth_key.0),
        _ => None,
    };

    let dispatcher = Dispatcher::new(&mode);
    DISPATCHER
        .set(dispatcher)
        .map_err(|_| "Lilith-Telemetry: init() called more than once!")
        .unwrap();

    if let Some(key_id) = member_key_id {
        // 1. Permanently set identity in thread-local baggage for the process lifetime.
        let mut persistent_baggage = crate::baggage::current();
        persistent_baggage.agent_id = key_id;
        persistent_baggage.session_id = crate::baggage::SessionId::generate();
        
        // trace_id and span_id stay at zero — each new telemetry_span! will
        // generate a fresh unique TraceID within this persistent session.
        crate::baggage::set_current(persistent_baggage);

        // 2. Emit SESSION_INIT with a *temporary* isolated trace/span.
        if let Some(d) = DISPATCHER.get() {
            let ts = crate::clock::rdtsc();
            let mut session_baggage = persistent_baggage;
            session_baggage.trace_id = crate::baggage::TraceId::generate();
            session_baggage.span_id  = crate::baggage::SpanId::generate();
            session_baggage.parent_span_id = None;
            d.dispatch_session_init(ts, session_baggage, b"SESSION_INIT".to_vec());
        }
    }
}

