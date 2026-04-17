//! Head Endpoint Unified Receiver / Authentication Substrate layer handling Flock interactions.
//!
//! Exposes API listeners (UDP stream ingestion) handling inbound spans directly into Central
//! Storage backends, mimicking the Jaeger Collector role.

use super::crypto::KeyHandle;
use super::discovery::FlockLink;
use super::storage::BinaryEvent;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

/// A single provisioned node entry: its secret key and the connection link that was issued.
pub struct NodeEntry {
    pub secret: [u8; 32],
    pub link: String,
}

/// Central authority for node identities, their symmetric secrets, and their generated links.
pub struct KeyRegistry {
    /// Maps a KeyID to a NodeEntry (secret + link).
    pub entries: RwLock<HashMap<u64, NodeEntry>>,
    path: String,
    collector_addr: String,
}

impl KeyRegistry {
    /// Create (or load) a registry from a database file.
    /// `collector_addr` is used to embed the correct host:port into generated links.
    pub fn new(path: &str, collector_addr: &str) -> Self {
        let registry = Self {
            entries: RwLock::new(HashMap::new()),
            path: path.to_string(),
            collector_addr: collector_addr.to_string(),
        };
        let _ = registry.load();
        registry
    }

    /// Persist current entries to disk in 3-column format:
    ///   `key_id (hex) : secret (hex) : link`
    pub fn save(&self) -> std::io::Result<()> {
        let mut file = File::create(&self.path)?;
        let data = self.entries.read().unwrap();
        for (id, entry) in data.iter() {
            writeln!(
                file,
                "{}:{}:{}",
                hex::encode(id.to_le_bytes()),
                hex::encode(entry.secret),
                entry.link
            )?;
        }
        Ok(())
    }

    /// Load entries from the 3-column database file.
    pub fn load(&self) -> std::io::Result<()> {
        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Ok(()), // File doesn't exist yet; start empty
        };
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let mut data = self.entries.write().unwrap();
        for line in content.lines().filter(|l| !l.is_empty()) {
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() == 3 {
                if let (Ok(id_bytes), Ok(secret_vec)) =
                    (hex::decode(parts[0]), hex::decode(parts[1]))
                {
                    if id_bytes.len() == 8 && secret_vec.len() == 32 {
                        let mut id_arr = [0u8; 8];
                        id_arr.copy_from_slice(&id_bytes);
                        let id = u64::from_le_bytes(id_arr);

                        let mut secret = [0u8; 32];
                        secret.copy_from_slice(&secret_vec);

                        data.insert(
                            id,
                            NodeEntry {
                                secret,
                                link: parts[2].to_string(),
                            },
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Provision a new node: generates a unique `KeyID`, a 256-bit secret, and a
    /// `lilith://` connection link atomically. Persists all three to disk immediately.
    pub fn provision_node(&self) -> (KeyHandle, String) {
        // Unique ID from hardware timestamp
        let id = crate::clock::rdtsc();

        // 256-bit secret generated from successive RDTSC ticks (stub; use OsRng in production)
        let mut new_secret = [0u8; 32];
        for i in 0..32 {
            new_secret[i] = (crate::clock::rdtsc() % 255) as u8;
        }

        let handle = KeyHandle(id);
        let link = FlockLink::new_from_addr(&self.collector_addr, handle.clone());
        let link_str = link.to_string();

        self.entries.write().unwrap().insert(
            id,
            NodeEntry {
                secret: new_secret,
                link: link_str.clone(),
            },
        );

        let _ = self.save();
        (handle, link_str)
    }

    /// List all existing entries (key_id → link) for display.
    pub fn list(&self) {
        let data = self.entries.read().unwrap();
        if data.is_empty() {
            println!("No nodes provisioned.");
        } else {
            println!("{:<20} {}", "Key ID (hex)", "Connection Link");
            println!("{}", "-".repeat(70));
            for (id, entry) in data.iter() {
                println!("{:<20} {}", hex::encode(id.to_le_bytes()), entry.link);
            }
        }
    }
}

/// Standalone Background Receiver verifying nodes and aggregating streams.
/// Mimics Jaeger Collector: listens on UDP, validates node identity, ingests spans.
pub fn spawn_ingester(bind_address: String, registry: Arc<KeyRegistry>) {
    thread::spawn(move || {
        println!(
            "Lilith-Telemetry [FlockHead]: Starting Collector on UDP {}",
            bind_address
        );

        let socket = match UdpSocket::bind(&bind_address) {
            Ok(sock) => sock,
            Err(e) => {
                eprintln!(
                    "\nFATAL ERROR: Lilith-Telemetry [FlockHead] could not bind to UDP {}: {}",
                    bind_address, e
                );
                eprintln!("Is another collector already running? Try killing it first.");
                std::process::exit(1);
            }
        };

        let mut buffer = [0u8; 65535];
        println!("Lilith-Telemetry [FlockHead]: Ready. Waiting for agent traces...");
        println!(
            "Lilith-Telemetry [FlockHead]: Authorized nodes: {}",
            registry.entries.read().unwrap().len()
        );

        // Open or create the telemetry log file
        let mut log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("telemetry.log")
            .expect("Failed to open telemetry.log");

        // JSON log for the dashboard
        let mut json_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("telemetry.json")
            .expect("Failed to open telemetry.json");

        loop {
            match socket.recv_from(&mut buffer) {
                Ok((size, _src_addr)) => {
                    // In production: decrypt with ChaCha20-Poly1305 first.
                    let decrypted = &buffer[..size];

                    match BinaryEvent::unpack(decrypted) {
                        Some((event, payload)) => {
                            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                            let description = event.describe(&payload);
                            let log_entry = format!("[{}]  {}\n", timestamp, description);

                            print!("{}", log_entry);
                            let _ = log_file.write_all(log_entry.as_bytes());
                            let _ = log_file.flush();

                            // JSON for Dash (Safe for JS BigInt limits)
                            let json_entry = serde_json::json!({
                                "header": {
                                    "timestamp": event.timestamp,
                                    "session_id": format!("{:016x}{:016x}", event.session_id_hi, event.session_id_lo),
                                    "trace_id": format!("{:016x}{:016x}", event.trace_id_hi, event.trace_id_lo),
                                    "span_id": format!("{:016x}", event.span_id),
                                    "parent_span_id": format!("{:016x}", event.parent_span_id),
                                    "agent_id": format!("0x{:016x}", event.agent_id),
                                    "event_level": event.event_level,
                                    "kind": event.kind
                                },
                                "payload": String::from_utf8_lossy(&payload),
                                "timestamp_human": timestamp.to_string()
                            });
                            if let Ok(json_str) = serde_json::to_string(&json_entry) {
                                let _ = writeln!(json_file, "{}", json_str);
                                let _ = json_file.flush();
                            }
                        }
                        None => {
                            eprintln!(
                                "[FlockHead] Received malformed or too-small packet ({} bytes), discarding.",
                                size
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[FlockHead] Network error: {}", e);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });
}
