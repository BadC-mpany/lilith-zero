
//! The internal Event definition enum and multi-core thread architecture mappings.

/// Specifies the severity scale and queue handling classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLevel {
    /// Zero-cost routing logic matching tracing capabilities.
    Trace,
    /// Fast Path - security blocks sent to isolated emergency queues.
    CriticalDeny,
    /// Slow Path - Execution metadata offloaded to kernel idle cycles.
    RoutineAllow,
}
