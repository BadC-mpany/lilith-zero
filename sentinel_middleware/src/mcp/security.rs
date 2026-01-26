use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use uuid::Uuid;
use anyhow::{Result, bail};
use rand::Rng;

pub struct SecurityEngine;

impl SecurityEngine {
    /// Applies 'Spotlighting' to the tool output.
    /// Wraps the content in randomized delimiters to prevent Prompt Injection.
    /// This makes it explicit to the LLM where the tool output starts and ends,
    /// preventing "instruction injection" attacks where the tool output mimics user instructions.
    pub fn spotlight(content: &str) -> String {
        let id: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        
        format!(
            "<<<SENTINEL_DATA_START:{}>>>\n{}\n<<<SENTINEL_DATA_END:{}>>>",
            id, content, id
        )
    }
}

pub struct SessionManager {
    secret: [u8; 32],
}

impl SessionManager {
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill(&mut secret);
        Self { secret }
    }

    /// Sign a Session ID (UUID) with the ephemeral secret.
    /// Returns Base64(UUID_BYTES + HMAC_TAG)
    /// This prevents session hijacking as the ID cannot be forged without the memory-only secret.
    pub fn create_session_token(&self) -> String {
        let id = Uuid::new_v4();
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC can take key of any size");
        mac.update(id.as_bytes());
        let result = mac.finalize();
        let tag = result.into_bytes();

        let mut token_bytes = Vec::with_capacity(16 + 32);
        token_bytes.extend_from_slice(id.as_bytes());
        token_bytes.extend_from_slice(&tag);

        BASE64.encode(token_bytes)
    }

    /// Verify and extract UUID from a signed token.
    /// Uses constant-time comparison via the `hmac` crate to prevent timing attacks.
    pub fn verify_token(&self, token: &str) -> Result<Uuid> {
        let token_bytes = BASE64.decode(token).map_err(|_| anyhow::anyhow!("Invalid Base64 token"))?;
        if token_bytes.len() != 48 { // 16 bytes UUID + 32 bytes HMAC-SHA256
            bail!("Invalid token length - expected 48 bytes (16 UUID + 32 HMAC)");
        }

        let (uuid_bytes, tag_bytes) = token_bytes.split_at(16);
        
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).expect("HMAC can take key of any size");
        mac.update(uuid_bytes);
        
        // verify_slice uses constant-time comparison
        if mac.verify_slice(tag_bytes).is_err() {
            bail!("Invalid session token signature - potential hijacking attempt");
        }

        Ok(Uuid::from_bytes(uuid_bytes.try_into().unwrap()))
    }
}
