//! Exporter Egress Tunnel — Jaeger Agent equivalent.
//! Encrypts and streams packed BinaryEvent bytes over UDP to the FlockHead Collector.

use super::DeploymentMode;
use super::crypto::EphemeralSession;
use std::net::UdpSocket;

/// UDP proxy that streams encrypted BinaryEvent payloads to the FlockHead.
pub struct EgressExporter {
    session: Option<EphemeralSession>,
    socket: Option<UdpSocket>,
    target_endpoint: Option<String>,
    agent_id: u64,
}

impl EgressExporter {
    pub fn new(mode: &DeploymentMode) -> Self {
        let (socket, target_endpoint, agent_id) = match mode {
            DeploymentMode::FlockMember {
                target_api_endpoint,
                auth_key,
            } => {
                let sock =
                    UdpSocket::bind("0.0.0.0:0").expect("Failed to bind local UDP Egress Socket");
                // Non-blocking: never stall the telemetry hot-path on network I/O.
                sock.set_nonblocking(true)
                    .expect("Failed to set Egress Socket to non-blocking");
                (Some(sock), Some(target_api_endpoint.clone()), auth_key.0)
            }
            _ => (None, None, 0),
        };

        Self {
            session: EphemeralSession::new(mode),
            socket,
            target_endpoint,
            agent_id,
        }
    }

    /// Encrypt and stream a fully packed BinaryEvent byte slice to the FlockHead.
    /// The packet IS the packed BinaryEvent — no extra headers needed.
    pub fn stream_payload(&self, packed_event: &[u8]) {
        if let (Some(session), Some(sock), Some(target)) =
            (&self.session, &self.socket, &self.target_endpoint)
        {
            // In production: encrypt the packed bytes with ChaCha20-Poly1305.
            // The encrypted envelope IS the wire packet.
            let encrypted = session.encrypt_blob(packed_event);
            if let Err(_) = sock.send_to(&encrypted, target) {
                self.emit_gap_marker();
            }
        }
    }

    /// Sends a "gap" BinaryEvent so the FlockHead knows this node dropped records.
    pub fn emit_gap_marker(&self) {
        if let (Some(session), Some(sock), Some(target)) =
            (&self.session, &self.socket, &self.target_endpoint)
        {
            // Construct a minimal gap event with zeroed trace/span context
            use crate::storage::BinaryEvent;
            let gap_payload = b"GAP";
            let baggage = crate::baggage::current();
            let event = BinaryEvent {
                timestamp: crate::clock::rdtsc(),
                session_id_hi: baggage.session_id.0,
                session_id_lo: baggage.session_id.1,
                trace_id_hi: 0,
                trace_id_lo: 0,
                span_id: 0,
                parent_span_id: 0,
                agent_id: self.agent_id,
                thread_id: 0,
                policy_id: 0,
                kind: 0,
                event_level: 254, // GAP_MARKER
                payload_len: gap_payload.len() as u16,
            };
            let packed = event.pack(gap_payload);
            let encrypted = session.encrypt_blob(&packed);
            let _ = sock.send_to(&encrypted, target);
        }
    }
}
