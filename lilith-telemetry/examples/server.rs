use lilith_telemetry::{DeploymentMode, KeyRegistry, init};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() {
    let registry_path = "flock_keys.db";
    let bind_addr = "127.0.0.1:44317";

    println!("--- Lilith Telemetry [FlockHead / Collector] ---");

    let registry = Arc::new(KeyRegistry::new(registry_path, bind_addr));

    let count = registry.entries.read().unwrap().len();
    println!(
        "Loaded {} authorized node(s) from '{}'",
        count, registry_path
    );
    println!("Data received from agents is stored locally by this process.");
    println!("(In production: written to the LSM-tree store on this machine's disk)");
    println!();

    init(DeploymentMode::FlockHead {
        bind_address: bind_addr.to_string(),
        registry,
    });

    println!(
        "Collector online at UDP {}. Press Ctrl+C to stop.\n",
        bind_addr
    );

    loop {
        thread::sleep(Duration::from_secs(60));
    }
}
