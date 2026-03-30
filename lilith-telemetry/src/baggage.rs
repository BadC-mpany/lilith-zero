
//! Context Propagation - Baggage System
//!
//! OTEL-like cross-boundary context propagation carrying the critical metadata
//! identifiers necessary for correlating disjointed async/network events.

use std::sync::atomic::{AtomicU64, Ordering};

/// 128-bit Trace IDs linking high-level agent intent to low-level syscall interdictions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceId(pub u64, pub u64);

/// 128-bit Session IDs identifying a single execution lifetime of an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64, pub u64);

/// 64-bit Span IDs identifying a single operation within a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpanId(pub u64);

/// Span Kind mapping to OpenTelemetry conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
    Internal = 0,
    Server = 1,
    Client = 2,
    Producer = 3,
    Consumer = 4,
}

impl SpanId {
    /// Generate a 64-bit span identifier.
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let ts = crate::clock::rdtsc();
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        SpanId(ts ^ seq)
    }
}

impl SessionId {
    /// Generate a unique session identifier.
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let ts = crate::clock::rdtsc();
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        SessionId(ts, seq)
    }
}

impl TraceId {
    /// Generate a localized sequence pseudo-UUIDv7 trace identifier.
    /// In production this integrates hardware RNG instructions.
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let ts = crate::clock::rdtsc();
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        TraceId(ts, seq)
    }
}

/// Core Context carrier moving through asynchronous boundaries.
#[derive(Debug, Clone, Copy)]
pub struct Baggage {
    pub agent_id: u64,
    pub session_id: SessionId,
    pub security_policy_id: u32,
    pub hardware_thread_id: u32,
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: Option<SpanId>,
    pub kind: SpanKind,
}

thread_local! {
    /// Thread-local storage backing current Execution Context.
    static CURRENT_BAGGAGE: std::cell::RefCell<Baggage> = std::cell::RefCell::new(Baggage {
        agent_id: 0,
        session_id: SessionId(0, 0),
        security_policy_id: 0,
        hardware_thread_id: 0,
        trace_id: TraceId(0, 0),
        span_id: SpanId(0),
        parent_span_id: None,
        kind: SpanKind::Internal,
    });
}

/// Retrieve the currently executing span baggage.
pub fn current() -> Baggage {
    CURRENT_BAGGAGE.with(|b| *b.borrow())
}

/// Overwrite the thread-local baggage for context injection.
pub fn set_current(baggage: Baggage) {
    CURRENT_BAGGAGE.with(|b| *b.borrow_mut() = baggage);
}

/// A scope guard that restores the previous baggage when dropped.
pub struct SpanGuard {
    previous: Baggage,
}

impl SpanGuard {
    pub fn new(new_baggage: Baggage) -> Self {
        let previous = current();
        set_current(new_baggage);
        Self { previous }
    }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        set_current(self.previous);
    }
}
