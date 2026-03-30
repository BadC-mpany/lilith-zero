
//! The Dispatcher (The Core)
//!
//! Stratified lock-free implementation utilizing a Ring Buffer layout, prioritizing
//! Security Critical Deny executions on primary cacheline boundaries.

use super::baggage::Baggage;
use super::exporter::EgressExporter;
use super::sampling::should_sample;
use super::storage::{BinaryEvent, LilithStore};
use super::DeploymentMode;

/// Denotes priority level associated directly through macros filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLevel {
    /// Critical security violations (Fast Path).
    /// Always pushed regardless of backpressure, may trigger synchronous stalling.
    CriticalDeny,
    /// General execution logs (Slow Path).
    /// Batched during idle cycles, deterministic gap drops allowed.
    RoutineAllow,
}

pub struct Dispatcher {
    store: LilithStore,
    exporter: EgressExporter,
}

impl Dispatcher {
    pub fn new(mode: &DeploymentMode) -> Self {
        let store = LilithStore::new();
        let exporter = EgressExporter::new(mode);
        Self { store, exporter }
    }

    /// Primary dispatch path. Constructs a packed BinaryEvent and routes it
    /// into the local store *and* streams it to the FlockHead in one call.
    pub fn dispatch(&self, level: EventLevel, ts_rdtsc: u64, baggage: Baggage, payload: Vec<u8>) {
        if !should_sample(level) {
            return;
        }

        let event_level_byte = match level {
            EventLevel::CriticalDeny  => 0u8,
            EventLevel::RoutineAllow  => 1u8,
        };

        let event = BinaryEvent {
            timestamp:       ts_rdtsc,
            session_id_hi:   baggage.session_id.0,
            session_id_lo:   baggage.session_id.1,
            trace_id_hi:     baggage.trace_id.0,
            trace_id_lo:     baggage.trace_id.1,
            span_id:         baggage.span_id.0,
            parent_span_id:  baggage.parent_span_id.map(|s| s.0).unwrap_or(0),
            agent_id:        baggage.agent_id,
            thread_id:       baggage.hardware_thread_id,
            policy_id:       baggage.security_policy_id,
            kind:            baggage.kind as u8,
            event_level:     event_level_byte,
            payload_len:     payload.len() as u16,
        };

        // Pack into a flat byte slice (the canonical on-wire and on-disk format)
        let packed = event.pack(&payload);

        match level {
            EventLevel::CriticalDeny => {
                if self.store.try_push_critical(ts_rdtsc, baggage, &payload).is_err() {
                    self.synchronous_emergency_flush();
                    let _ = self.store.try_push_critical(ts_rdtsc, baggage, &payload);
                }
                // Immediately stream the full packed BinaryEvent to the collector
                self.exporter.stream_payload(&packed);
            }
            EventLevel::RoutineAllow => {
                if self.store.try_push_routine(ts_rdtsc, baggage, &payload).is_err() {
                    self.exporter.emit_gap_marker();
                } else {
                    self.exporter.stream_payload(&packed);
                }
            }
        }
    }

    /// Emit a special SESSION_INIT event (level 255) when a node joins the flock.
    /// This appears in the FlockHead's log as the very first entry for this node.
    pub fn dispatch_session_init(&self, ts_rdtsc: u64, baggage: Baggage, payload: Vec<u8>) {
        let event = BinaryEvent {
            timestamp:      ts_rdtsc,
            session_id_hi:  baggage.session_id.0,
            session_id_lo:  baggage.session_id.1,
            trace_id_hi:    baggage.trace_id.0,
            trace_id_lo:    baggage.trace_id.1,
            span_id:        baggage.span_id.0,
            parent_span_id: 0,
            agent_id:       baggage.agent_id,
            thread_id:      baggage.hardware_thread_id,
            policy_id:      baggage.security_policy_id,
            kind:           baggage.kind as u8,
            event_level:    255, // SESSION_INIT marker
            payload_len:    payload.len() as u16,
        };
        let packed = event.pack(&payload);
        self.store.write_session_init_to_local_log(ts_rdtsc, &baggage, &payload);
        self.exporter.stream_payload(&packed);
    }

    #[cold]
    fn synchronous_emergency_flush(&self) {
        self.store.emergency_flush();
    }
}
