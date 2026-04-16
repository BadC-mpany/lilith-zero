// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, TryRngCore};
use sha2::Sha256;
use uuid::Uuid;

use crate::engine_core::constants::crypto;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 signer used for session ID generation and audit-log signing.
///
/// Holds an ephemeral 32-byte secret generated at process startup;
/// the secret never leaves the process.
#[derive(Clone)]
pub struct CryptoSigner {
    secret: [u8; crypto::SECRET_KEY_LENGTH],
}

use crate::engine_core::errors::{CryptoError, InterceptorError};

impl CryptoSigner {
    /// Generate a new [`CryptoSigner`] with a fresh ephemeral secret from the OS RNG.
    ///
    /// The returned `Result` must be checked; a failure here means the OS RNG is unavailable,
    /// which is a fatal startup condition.
    #[must_use = "crypto initialization result must be checked"]
    pub fn try_new() -> Result<Self, InterceptorError> {
        let mut secret = [0u8; crypto::SECRET_KEY_LENGTH];
        OsRng
            .try_fill_bytes(&mut secret)
            .map_err(|_| InterceptorError::CryptoError(CryptoError::RandomError))?;
        Ok(Self { secret })
    }

    /// Sign `data` with the signer's HMAC secret and return a URL-safe base64 encoded MAC.
    pub fn sign(&self, data: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC should accept secret of correct length");
        mac.update(data);
        let result = mac.finalize();
        URL_SAFE_NO_PAD.encode(result.into_bytes())
    }

    /// Generate a new session ID token of the form `{version}.{uuid_b64}.{hmac_b64}`.
    ///
    /// The HMAC binds the UUID to this signer's secret, enabling constant-time validation
    /// without persistent storage.
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

    /// Validate a session ID token using constant-time HMAC comparison.
    ///
    /// Returns `true` if the token was produced by this signer, `false` otherwise.
    /// A return value of `false` must be treated as an authentication failure.
    #[must_use = "session validation result must be checked"]
    pub fn validate_session_id(&self, session_id: &str) -> bool {
        let parts: Vec<&str> = session_id.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        if parts[0] != crypto::SESSION_ID_VERSION {
            return false;
        }

        let uuid_b64 = parts[1];
        let sig_b64 = parts[2];

        let uuid_bytes = match URL_SAFE_NO_PAD.decode(uuid_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let mut mac = match HmacSha256::new_from_slice(&self.secret) {
            Ok(m) => m,
            Err(_) => return false, // Should be impossible with correct key size, but fail safe
        };
        mac.update(&uuid_bytes);

        let provided_sig = match URL_SAFE_NO_PAD.decode(sig_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };

        mac.verify_slice(&provided_sig).is_ok()
    }
}
