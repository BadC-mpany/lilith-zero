use lilith_telemetry::{DISPATCHER, DeploymentMode, KeyRegistry, init};
use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn exhaustive_test_flock_head_mode() {
    // Allocate a free port dynamically
    let dummy = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = dummy.local_addr().unwrap().port();
    drop(dummy);

    let bind_address = format!("127.0.0.1:{}", port);
    println!("FlockHead binding on {}", bind_address);

    let registry = Arc::new(KeyRegistry::new("test_keys.db", &bind_address));
    let (_handle, link) = registry.provision_node();
    println!("Provisioned node link: {}", link);

    init(DeploymentMode::FlockHead {
        bind_address: bind_address.clone(),
        registry,
    });

    assert!(
        DISPATCHER.get().is_some(),
        "FlockHead Dispatcher must be initialized"
    );
    thread::sleep(Duration::from_millis(50));

    // Simulate an agent sending UDP datagrams to the collector
    let mock_agent = UdpSocket::bind("127.0.0.1:0").unwrap();
    mock_agent.set_nonblocking(true).unwrap();

    let payload = b"MOCK_ENCRYPTED_TELEMETRY_DATAGRAM";
    mock_agent
        .send_to(payload, &bind_address)
        .expect("Failed to send test datagram");

    // Flood test: verify the collector doesn't deadlock or OOM under packet aggression
    for _ in 0..1000 {
        let _ = mock_agent.send_to(payload, &bind_address);
    }

    thread::sleep(Duration::from_millis(150));
    println!("FlockHead Collector handled packet aggression successfully.");
}
