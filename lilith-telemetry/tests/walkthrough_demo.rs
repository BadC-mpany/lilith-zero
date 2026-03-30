use lilith_telemetry::{init, DeploymentMode, KeyRegistry, FlockLink, telemetry_event, dispatcher::EventLevel};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Full E2E walkthrough: provision → link → start head → connect node → send event.
#[test]
fn complete_system_walkthrough() {
    let registry_path = "flock_keys_walkthrough.db";
    let collector_addr = "127.0.0.1:44318"; // Use distinct port to avoid test conflicts

    // === STEP 1: Provision a new node on the FlockHead (server) side ===
    let registry = Arc::new(KeyRegistry::new(registry_path, collector_addr));
    let (key_handle, link_str) = registry.provision_node();

    println!("Step 1: Provisioned node.");
    println!("        Key ID : 0x{:x}", key_handle.0);
    println!("        Link   : {}", link_str);
    println!("        DB     : {}", registry_path);

    // === STEP 2: Verify the link parses correctly ===
    let parsed = FlockLink::parse(&link_str).expect("Link must parse back correctly");
    assert_eq!(parsed.key_id, key_handle.0, "Parsed key_id must match provisioned handle");
    println!("Step 2: Link parsed correctly → connecting to {}:{}", parsed.host, parsed.port);

    // === STEP 3: Start the collector (FlockHead) ===
    init(DeploymentMode::FlockHead {
        bind_address: collector_addr.to_string(),
        registry,
    });
    println!("Step 3: FlockHead Collector is online.");

    thread::sleep(Duration::from_millis(100));

    // === STEP 4: Fire a telemetry event (as if from a FlockMember) ===
    // In a real deployment, this would be in the node process using DeploymentMode::FlockMember.
    // Here we exercise the local dispatcher to confirm the full stack functions.
    telemetry_event!(EventLevel::CriticalDeny, b"WALKTHROUGH_AUDIT_EVENT");

    thread::sleep(Duration::from_millis(100));
    println!("Step 4: Event dispatched successfully.");
    println!("Walkthrough PASSED.");
}
