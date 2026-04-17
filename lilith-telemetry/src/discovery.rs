//! Flock Discovery and Connection Link generation logic.

use super::crypto::KeyHandle;
use std::fmt;

/// Represents a secure connection directive for a Lilith node.
pub struct FlockLink {
    pub host: String,
    pub port: u16,
    pub key_id: u64,
}

impl FlockLink {
    /// Generates a link from explicit host/port and a key.
    pub fn new(host: &str, port: u16, key: KeyHandle) -> Self {
        Self {
            host: host.to_string(),
            port,
            key_id: key.0,
        }
    }

    /// Generates a link from an already-formatted `"host:port"` address string.
    pub fn new_from_addr(addr: &str, key: KeyHandle) -> Self {
        let mut parts = addr.splitn(2, ':');
        let host = parts.next().unwrap_or("127.0.0.1").to_string();
        let port = parts.next().and_then(|p| p.parse().ok()).unwrap_or(44317);
        Self {
            host,
            port,
            key_id: key.0,
        }
    }

    /// Parses a `"lilith://"` URI into a FlockLink.
    pub fn parse(uri: &str) -> Result<Self, String> {
        if !uri.starts_with("lilith://") {
            return Err("Invalid protocol scheme. Use lilith://".to_string());
        }

        let body = &uri[9..];
        let mut parts = body.splitn(2, '?');
        let addr_part = parts.next().ok_or("Missing address")?;
        let query_part = parts.next().ok_or("Missing key_id query parameter")?;

        let mut addr_split = addr_part.splitn(2, ':');
        let host = addr_split.next().ok_or("Missing host")?.to_string();
        let port = addr_split
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(44317);

        let mut key_id = 0u64;
        for param in query_part.split('&') {
            if let Some(val) = param.strip_prefix("key_id=") {
                key_id = u64::from_str_radix(val.trim_start_matches("0x"), 16)
                    .map_err(|_| "Invalid key_id hex format")?;
            }
        }

        if key_id == 0 {
            return Err("No valid key_id found in link".to_string());
        }

        Ok(Self { host, port, key_id })
    }
}

impl fmt::Display for FlockLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "lilith://{}:{}?key_id=0x{:x}",
            self.host, self.port, self.key_id
        )
    }
}
