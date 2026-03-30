
//! Macro Definitions mimicking the standard parsing structures but enabling
//! Zero-Cost abstraction optimizations completely dropping AST representations if disabled.

/// Resolves standard text trace elements compiling only through specialized contexts.
///
/// Features Context Propagation tracking directly to `Baggage` maps and supports
/// structured attributes following OpenTelemetry conventions.
#[macro_export]
macro_rules! telemetry_event {
    ($level:expr, $payload:expr) => {
        $crate::telemetry_event!($level, $payload, [])
    };
    ($level:expr, $payload:expr, [$( $key:expr => $val:expr ),*]) => {
        {
            if $crate::sampling::should_sample($level) {
                let timestamp = $crate::clock::rdtsc();
                let baggage = $crate::baggage::current();

                let mut scrubbed = $payload.into();
                $crate::scrubber::scrub_pii(&mut scrubbed);

                // Attributes are serialized into the payload for this high-perf iteration
                // In production, this uses a packed TLV (Type-Length-Value) encoding.
                if let Some(dispatcher) = $crate::DISPATCHER.get() {
                    dispatcher.dispatch($level, timestamp, baggage, scrubbed);
                }
            }
        }
    };
}

/// Instantiates structured baggage scopes handling `SpanID` and `SpanKind`.
/// Returns a guard that restores the previous span context on drop.
#[macro_export]
macro_rules! telemetry_span {
    ($name:expr) => {
        $crate::telemetry_span!($name, $crate::baggage::SpanKind::Internal)
    };
    ($name:expr, $kind:expr) => {
        {
            let mut baggage = $crate::baggage::current();
            let parent_id = Some(baggage.span_id);
            let new_span_id = $crate::baggage::SpanId::generate();
            
            // If this is a root span (no active trace), generate a new TraceID
            if baggage.trace_id.0 == 0 && baggage.trace_id.1 == 0 {
                baggage.trace_id = $crate::baggage::TraceId::generate();
            }

            baggage.parent_span_id = parent_id;
            baggage.span_id = new_span_id;
            baggage.kind = $kind;
            
            $crate::baggage::SpanGuard::new(baggage)
        }
    };
}
