// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and


use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::Sha256;
use uuid::Uuid;

use crate::engine_core::constants::crypto;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct CryptoSigner {
    secret: [u8; crypto::SECRET_KEY_LENGTH],
}

use crate::engine_core::errors::{CryptoError, InterceptorError};


impl CryptoSigner {
    #[must_use = "crypto initialization result must be checked"]
    pub fn try_new() -> Result<Self, InterceptorError> {
        // Description: Executes the try_new logic.
        let rng = SystemRandom::new();
        let mut secret = [0u8; crypto::SECRET_KEY_LENGTH];
        rng.fill(&mut secret)
            .map_err(|_| InterceptorError::CryptoError(CryptoError::RandomError))?;
        Ok(Self { secret })
    }

    pub fn sign(&self, data: &[u8]) -> String {
        // Description: Executes the sign logic.
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC should accept secret of correct length");
        mac.update(data);
        let result = mac.finalize();
        URL_SAFE_NO_PAD.encode(result.into_bytes())
    }

    pub fn generate_session_id(&self) -> Result<String, InterceptorError> {
        // Description: Executes the generate_session_id logic.
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

    #[must_use = "session validation result must be checked"]
    pub fn validate_session_id(&self, session_id: &str) -> bool {
        // Description: Executes the validate_session_id logic.
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
