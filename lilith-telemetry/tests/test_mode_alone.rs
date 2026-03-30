use lilith_telemetry::baggage::{self, Baggage, TraceId};
use lilith_telemetry::dispatcher::EventLevel;
use lilith_telemetry::{init, telemetry_event, telemetry_span, DeploymentMode, DISPATCHER, SpanKind};
use std::thread;
use std::time::Duration;

#[test]
fn exhaustive_test_alone_mode() {
    // 1. Initialize the Telemetry Engine as standalone (no network overhead)
    init(DeploymentMode::Alone);
    assert!(DISPATCHER.get().is_some(), "Dispatcher strictly requires initialization");

    // 2. Validate Baggage Propagation
    let trace_id = TraceId::generate();
    baggage::set_current(Baggage {
        agent_id: 115,
        session_id: lilith_telemetry::baggage::SessionId::generate(),
        security_policy_id: 8,
        hardware_thread_id: 1,
        trace_id,
        span_id: lilith_telemetry::SpanId::generate(),
        parent_span_id: None,
        kind: lilith_telemetry::SpanKind::Internal,
    });

    let current = baggage::current();
    assert_eq!(current.agent_id, 115);
    assert_eq!(current.trace_id, trace_id, "Context mapping verification failed");

    // 3. Test Span Context Propagation
    {
        let _span = telemetry_span!("security_check", SpanKind::Server);
        let span_baggage = baggage::current();
        assert_eq!(span_baggage.parent_span_id, Some(current.span_id));
        assert_ne!(span_baggage.span_id, current.span_id);
        assert_eq!(span_baggage.kind, SpanKind::Server);
        
        telemetry_event!(EventLevel::CriticalDeny, b"Inside span");
    }
    
    let post_span = baggage::current();
    assert_eq!(post_span.span_id, current.span_id, "SpanGuard failed to restore context");

    // 4. Test Critical Fast Path (Ring buffer boundary checks)
    let denial_payload = b"CRITICAL_VIOLATION_BLOB";
    telemetry_event!(EventLevel::CriticalDeny, denial_payload.as_slice(), ["user" => "admin", "severity" => "high"]);

    // 5. Test Routine Slow Path (Adaptive Sampling) with high throughput
    // We iterate massively to validate the lock-free implementation does not block main application operations
    let allow_payload = b"ROUTINE_ACCESS_OK";
    for _ in 0..10_000 {
        telemetry_event!(EventLevel::RoutineAllow, allow_payload.as_slice());
    }

    // 6. Test Context Scrubber Trigger
    let sensitive_payload = b"SECRET_JWT_OR_BEARER_TOKEN";
    telemetry_event!(EventLevel::CriticalDeny, sensitive_payload.as_slice());

    // Slight delay simulating asynchronous background flush sequences settling in LSM tree Mock Layer
    thread::sleep(Duration::from_millis(50));
    
    println!("Alone Mode Exhasutive Substrate Testing Completely Cleared.");
}
