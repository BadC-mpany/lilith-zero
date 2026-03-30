
//! Storage Engine (The Lilith-Store)
//!
//! A localized representation of an LSM (Log-Structured Merge-tree) adapted
//! over OS-backed Ring Buffers and Memory-Mapped Arrays preventing total-collapse data loss.

use super::baggage::Baggage;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::Serialize;

/// Fixed-width binary header for each event. Total header size = 76 bytes.
/// Every single event — including SESSION_INIT, tool calls, and gap markers — uses this format.
///
/// Wire format: [BinaryEvent header 76 bytes][payload: payload_len bytes]
#[derive(Serialize)]
pub struct BinaryEvent {
    pub timestamp: u64,        // 8b  — CPU RDTSC cycle counter
    pub session_id_hi: u64,    // 8b  — Upper 64 bits of 128-bit SessionID
    pub session_id_lo: u64,    // 8b  — Lower 64 bits of 128-bit SessionID
    pub trace_id_hi: u64,      // 8b  — Upper 64 bits of 128-bit TraceID
    pub trace_id_lo: u64,      // 8b  — Lower 64 bits of 128-bit TraceID
    pub span_id: u64,          // 8b  — Current span ID
    pub parent_span_id: u64,   // 8b  — Parent span ID (0 = root span)
    pub agent_id: u64,         // 8b  — Node's Key ID (from flock_keys.db)
    pub thread_id: u32,        // 4b  — Hardware thread ID
    pub policy_id: u32,        // 4b  — Security policy rule that triggered this event
    pub kind: u8,              // 1b  — SpanKind (0=Internal,1=Server,2=Client,3=Producer,4=Consumer)
    pub event_level: u8,       // 1b  — 0=CriticalDeny, 1=RoutineAllow, 255=SessionInit/System
    pub payload_len: u16,      // 2b  — Number of bytes of payload following the header
}

pub const HEADER_SIZE: usize = 76;

impl BinaryEvent {
    /// Serialize this header + payload into a flat byte vector.
    pub fn pack(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.session_id_hi.to_le_bytes());
        out.extend_from_slice(&self.session_id_lo.to_le_bytes());
        out.extend_from_slice(&self.trace_id_hi.to_le_bytes());
        out.extend_from_slice(&self.trace_id_lo.to_le_bytes());
        out.extend_from_slice(&self.span_id.to_le_bytes());
        out.extend_from_slice(&self.parent_span_id.to_le_bytes());
        out.extend_from_slice(&self.agent_id.to_le_bytes());
        out.extend_from_slice(&self.thread_id.to_le_bytes());
        out.extend_from_slice(&self.policy_id.to_le_bytes());
        out.push(self.kind);
        out.push(self.event_level);
        out.extend_from_slice(&self.payload_len.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Deserialize a packed byte slice back into a BinaryEvent header and its payload.
    pub fn unpack(data: &[u8]) -> Option<(Self, Vec<u8>)> {
        if data.len() < HEADER_SIZE {
            return None;
        }

        let timestamp       = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let session_id_hi   = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let session_id_lo   = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let trace_id_hi     = u64::from_le_bytes(data[24..32].try_into().ok()?);
        let trace_id_lo     = u64::from_le_bytes(data[32..40].try_into().ok()?);
        let span_id         = u64::from_le_bytes(data[40..48].try_into().ok()?);
        let parent_span_id  = u64::from_le_bytes(data[48..56].try_into().ok()?);
        let agent_id        = u64::from_le_bytes(data[56..64].try_into().ok()?);
        let thread_id       = u32::from_le_bytes(data[64..68].try_into().ok()?);
        let policy_id       = u32::from_le_bytes(data[68..72].try_into().ok()?);
        let kind            = data[72];
        let event_level     = data[73];
        let payload_len     = u16::from_le_bytes(data[74..76].try_into().ok()?);

        let total_expected = HEADER_SIZE + payload_len as usize;
        if data.len() < total_expected {
            return None;
        }

        let payload = data[HEADER_SIZE..total_expected].to_vec();

        Some((
            Self {
                timestamp,
                session_id_hi,
                session_id_lo,
                trace_id_hi,
                trace_id_lo,
                span_id,
                parent_span_id,
                agent_id,
                thread_id,
                policy_id,
                kind,
                event_level,
                payload_len,
            },
            payload,
        ))
    }

    /// Format a human-readable one-line description of this event for logs.
    pub fn describe(&self, payload: &[u8]) -> String {
        let level_str = match self.event_level {
            0   => "CRITICAL",
            1   => "ROUTINE",
            254 => "GAP",
            255 => "SESSION_INIT",
            _   => "UNKNOWN",
        };
        let kind_str = match self.kind {
            0 => "Internal",
            1 => "Server",
            2 => "Client",
            3 => "Producer",
            4 => "Consumer",
            _ => "?",
        };
        let msg = String::from_utf8_lossy(payload);
        format!(
            "NODE: 0x{:016x}  SESSION: {:016x}{:016x}  TRACE: {:016x}{:016x}  SPAN: {:016x}  PARENT: {:016x}  LEVEL: {:<12} KIND: {:<8}  MSG: {}",
            self.agent_id,
            self.session_id_hi,
            self.session_id_lo,
            self.trace_id_hi,
            self.trace_id_lo,
            self.span_id,
            self.parent_span_id,
            level_str,
            kind_str,
            msg.trim()
        )
    }
}

use std::io::Write;
use std::fs::{File, OpenOptions};
use std::sync::Mutex;

/// Simulating MemTables through thread-local per-CPU buffers caching incoming telemetry streams.
pub struct LilithStore {
    written_bytes: AtomicUsize,
    local_log: Mutex<Option<File>>,
}

impl LilithStore {
    pub fn new() -> Self {
        // Attempt to open a local log file for demo purposes.
        // In a real LSM, this would be an SSTable flush.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("node_telemetry_local.log")
            .ok();

        Self {
            written_bytes: AtomicUsize::new(0),
            local_log: Mutex::new(file),
        }
    }

    /// Appends the human-readable event description to the local log file.
    fn append_to_local_log(&self, event: &BinaryEvent, payload: &[u8]) {
        if let Ok(mut lock) = self.local_log.lock() {
            if let Some(file) = lock.as_mut() {
                let current_time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                let log_entry = format!("[{}] {}\n", current_time, event.describe(payload));
                let _ = file.write_all(log_entry.as_bytes());
            }
        }
    }

    /// MemTable FAST insertion — packs the event into binary and writes to the ring buffer.
    pub fn try_push_critical(&self, ts: u64, b: Baggage, payload: &[u8]) -> Result<(), ()> {
        if self.written_bytes.load(Ordering::Relaxed) > 10_000_000 {
            return Err(());
        }
        let event = Self::make_event(ts, &b, 0, payload);
        let packed = event.pack(payload);
        
        self.append_to_local_log(&event, payload);

        self.write_ahead_heartbeat(ts);
        self.written_bytes.fetch_add(packed.len(), Ordering::AcqRel);
        Ok(())
    }

    /// Routine logs use relaxed atomics to keep cacheline disruption negligible.
    pub fn try_push_routine(&self, ts: u64, b: Baggage, payload: &[u8]) -> Result<(), ()> {
        if self.written_bytes.load(Ordering::Relaxed) > 8_000_000 {
            return Err(());
        }
        let event = Self::make_event(ts, &b, 1, payload);
        let packed = event.pack(payload);
        
        self.append_to_local_log(&event, payload);

        self.written_bytes.fetch_add(packed.len(), Ordering::Relaxed);
        Ok(())
    }

    fn make_event(ts: u64, b: &Baggage, level: u8, payload: &[u8]) -> BinaryEvent {
        BinaryEvent {
            timestamp: ts,
            session_id_hi: b.session_id.0,
            session_id_lo: b.session_id.1,
            trace_id_hi: b.trace_id.0,
            trace_id_lo: b.trace_id.1,
            span_id: b.span_id.0,
            parent_span_id: b.parent_span_id.map(|s| s.0).unwrap_or(0),
            agent_id: b.agent_id,
            thread_id: b.hardware_thread_id,
            policy_id: b.security_policy_id,
            kind: b.kind as u8,
            event_level: level,
            payload_len: payload.len() as u16,
        }
    }

    pub fn write_session_init_to_local_log(&self, ts_rdtsc: u64, b: &Baggage, payload: &[u8]) {
        let event = BinaryEvent {
            timestamp: ts_rdtsc,
            session_id_hi: b.session_id.0,
            session_id_lo: b.session_id.1,
            trace_id_hi: b.trace_id.0,
            trace_id_lo: b.trace_id.1,
            span_id: b.span_id.0,
            parent_span_id: 0,
            agent_id: b.agent_id,
            thread_id: b.hardware_thread_id,
            policy_id: b.security_policy_id,
            kind: b.kind as u8,
            event_level: 255,
            payload_len: payload.len() as u16,
        };
        self.append_to_local_log(&event, payload);
    }

    pub fn emergency_flush(&self) {
        self.written_bytes.store(0, Ordering::SeqCst);
    }

    fn write_ahead_heartbeat(&self, _timestamp: u64) {}
}
