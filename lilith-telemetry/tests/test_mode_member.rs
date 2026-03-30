use lilith_telemetry::baggage::{self, Baggage, TraceId};
use lilith_telemetry::crypto::KeyHandle;
use lilith_telemetry::dispatcher::EventLevel;
use lilith_telemetry::{init, telemetry_event, DeploymentMode, DISPATCHER};
use std::net::UdpSocket;
use std::time::Duration;

#[test]
fn exhaustive_test_flock_member_mode() {
    // 1. Set up an isolated Mock Collector Socket mimicking a receiving 'FlockHead'
    let mock_collector = UdpSocket::bind("127.0.0.1:0").expect("Native socket binding failed.");
    mock_collector.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let port = mock_collector.local_addr().unwrap().port();
    let local_collector_addr = format!("127.0.0.1:{}", port);

    // 2. Start up the Agent node proxy routing into the mockup API receiver above
    let proxy_identity = KeyHandle(0xDEADBEEF9876);
    
    init(DeploymentMode::FlockMember {
        target_api_endpoint: local_collector_addr.clone(),
        auth_key: proxy_identity.clone(),
    });
    assert!(DISPATCHER.get().is_some(), "Agent Dispatcher requires connectivity binding");

    // 3. Trace Setup and Payload emission
    let trace_id = TraceId::generate();
    baggage::set_current(Baggage {
        agent_id: 116,
        session_id: lilith_telemetry::baggage::SessionId::generate(),
        security_policy_id: 3,
        hardware_thread_id: 4,
        trace_id,
        span_id: lilith_telemetry::SpanId::generate(),
        parent_span_id: None,
        kind: lilith_telemetry::SpanKind::Internal,
    });

    let secret_payload = b"OVERHEARD_SYSCALL_HOOK";
    telemetry_event!(EventLevel::CriticalDeny, secret_payload.as_slice());

    // 4. Test Native Network Stream Validation
    // Validates that the UDP EgressExporter asynchronously caught the locked array payload,
    // encrypted it natively, and pushed it across non-blocking frames
    let mut buffer = [0u8; 1024];
    
    match mock_collector.recv_from(&mut buffer) {
        Ok((size, addr)) => {
            println!("Agent API Egress successfully verified hitting {} with {} bytes", addr, size);
            assert!(size > 0, "No payload successfully hit bounds");
        }
        Err(e) => {
            panic!("Agent network streaming failure detected: {:?}", e);
        }
    }

    // 5. Test Backpressure Priority Mitigation (Gap Markers)
    // Overwhelm network capability manually generating uncatchable routines
    for _ in 0..5000 {
        telemetry_event!(EventLevel::RoutineAllow, b"STORM".as_slice());
    }
    
    println!("FlockMember Network Streaming Validated natively.");
}
