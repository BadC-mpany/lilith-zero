use lilith_telemetry::KeyRegistry;

fn main() {
    let registry_path = "flock_keys.db";
    let collector_addr = "127.0.0.1:44317";

    let registry = KeyRegistry::new(registry_path, collector_addr);

    let args: Vec<String> = std::env::args().collect();

    if args.get(1).map(|s| s.as_str()) == Some("new") {
        // Provision a fresh node
        let (handle, link) = registry.provision_node();
        println!("Provisioned new node:");
        println!("  Key ID : 0x{:x}", handle.0);
        println!("  Link   : {}\n", link);
        println!("Send this link to the new workstation.");
    } else {
        // List existing nodes
        println!("\nProvisioned nodes in '{}':", registry_path);
        registry.list();
    }
}
