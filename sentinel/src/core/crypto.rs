//! Cryptographic utilities for session management and integrity.
//!
//! This module provides the `CryptoSigner` which handles HMAC-based session ID
//! generation and validation, ensuring that session identifiers are tamper-proof.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;
use uuid::Uuid;

use crate::core::constants::crypto;

type HmacSha256 = Hmac<Sha256>;

pub struct CryptoSigner {
    secret: [u8; crypto::SECRET_KEY_LENGTH],
}

use crate::core::errors::{CryptoError, InterceptorError};

// ... imports remain ...

impl CryptoSigner {
    /// Create a new signer with a secure random ephemeral key
    pub fn try_new() -> Result<Self, InterceptorError> {
        let rng = SystemRandom::new();
        let mut secret = [0u8; crypto::SECRET_KEY_LENGTH];
        rng.fill(&mut secret)
            .map_err(|_| InterceptorError::CryptoError(CryptoError::RandomError))?;
        Ok(Self { secret })
    }

    /// Generate a cryptographically bound Session ID
    /// Format: "{version}.{uuid_b64}.{hmac_b64}"
    pub fn generate_session_id(&self) -> Result<String, InterceptorError> {
        let uuid = Uuid::new_v4();
        let uuid_bytes = uuid.as_bytes();

        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|e| InterceptorError::CryptoError(CryptoError::HashingError(e.to_string())))?;

        mac.update(uuid_bytes);
        let result = mac.finalize();
        let signature = result.into_bytes();

        let uuid_b64 = URL_SAFE_NO_PAD.encode(uuid_bytes);
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature);

        Ok(format!(
            "{}.{}.{}",
            crypto::SESSION_ID_VERSION,
            uuid_b64,
            sig_b64
        ))
    }

    /// Validate a Session ID's integrity using constant-time comparison
    pub fn validate_session_id(&self, session_id: &str) -> bool {
        let parts: Vec<&str> = session_id.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        // Check version
        if parts[0] != crypto::SESSION_ID_VERSION {
            return false;
        }

        let uuid_b64 = parts[1];
        let sig_b64 = parts[2];

        // Decode UUID
        let uuid_bytes = match URL_SAFE_NO_PAD.decode(uuid_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // Re-compute HMAC
        let mut mac = match HmacSha256::new_from_slice(&self.secret) {
            Ok(m) => m,
            Err(_) => return false, // Should be impossible with correct key size, but fail safe
        };
        mac.update(&uuid_bytes);

        // Decode provided signature
        let provided_sig = match URL_SAFE_NO_PAD.decode(sig_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // Constant-time verify
        mac.verify_slice(&provided_sig).is_ok()
    }
}
