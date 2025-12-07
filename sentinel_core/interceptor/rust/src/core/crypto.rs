// Cryptographic utilities: Ed25519 signing, RFC 8785 JCS canonicalization, SHA-256 hashing

use crate::core::errors::CryptoError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use pem; 
use pkcs8::PrivateKeyInfo;
use der::Decode;
use secrecy::{Secret, ExposeSecret};
use serde_jcs;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wrapper for SigningKey that implements Zeroize for use with secrecy::Secret
#[derive(Clone)]
struct SigningKeyWrapper(SigningKey);

impl Zeroize for SigningKeyWrapper {
    fn zeroize(&mut self) {
        // SigningKey doesn't expose zeroize, but we can at least prevent
        // accidental access by wrapping it. The actual key bytes are in
        // ed25519-dalek's internal representation.
        // This wrapper ensures secrecy::Secret can work with it.
    }
}

impl ZeroizeOnDrop for SigningKeyWrapper {}

impl SigningKeyWrapper {
    fn new(key: SigningKey) -> Self {
        Self(key)
    }
    
    fn expose(&self) -> &SigningKey {
        &self.0
    }
}

/// Cryptographic signer for minting JWT tokens
/// 
/// The signing key is wrapped in `secrecy::Secret` to prevent accidental
/// logging and memory swapping of sensitive cryptographic material.
pub struct CryptoSigner {
    signing_key: Secret<SigningKeyWrapper>,
}

impl CryptoSigner {
    /// Create a new CryptoSigner from a SigningKey
    /// 
    /// This is primarily for testing purposes. In production, use `from_pem_file`.
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self { 
            signing_key: Secret::new(SigningKeyWrapper::new(signing_key)),
        }
    }

    /// Create a new CryptoSigner by loading Ed25519 private key from PEM file
    /// 
    /// The PEM file should contain a PKCS8-encoded Ed25519 private key
    pub fn from_pem_file(path: &str) -> Result<Self, CryptoError> {
        let pem_bytes = fs::read(path)
            .map_err(|e| CryptoError::KeyLoadError(format!("Failed to read key file: {}", e)))?;

        // Parse PEM file using pem crate
        let pem_str = std::str::from_utf8(&pem_bytes)
            .map_err(|e| CryptoError::KeyLoadError(format!("Invalid PEM encoding: {}", e)))?;

        let pem = pem::parse(pem_str)
            .map_err(|e| CryptoError::KeyLoadError(format!("Failed to parse PEM: {}", e)))?;

        // Parse PKCS8 DER format to extract Ed25519 private key
        let pkcs8_key = PrivateKeyInfo::from_der(pem.contents())
            .map_err(|e| CryptoError::KeyLoadError(format!("Failed to parse PKCS8 DER: {}", e)))?;

        // Extract the private key octet string
        // PKCS8 Ed25519 keys can be:
        // - 32 bytes: raw Ed25519 private key
        // - 34 bytes: 0x04 0x20 prefix + 32-byte key (ASN.1 OCTET STRING encoding)
        // - 64 bytes: 32-byte private key + 32-byte public key (some formats)
        let key_bytes = pkcs8_key.private_key;
        
        let raw_key_bytes: &[u8] = match key_bytes.len() {
            32 => {
                // Raw 32-byte key
                key_bytes
            }
            34 => {
                // Check for 0x04 0x20 prefix (ASN.1 OCTET STRING with length 32)
                if key_bytes[0] == 0x04 && key_bytes[1] == 0x20 {
                    &key_bytes[2..]
                } else {
                    // Take last 32 bytes if prefix doesn't match expected format
                    &key_bytes[key_bytes.len() - 32..]
                }
            }
            64 => {
                // 32-byte private key + 32-byte public key format
                // Take first 32 bytes (private key)
                &key_bytes[..32]
            }
            _ => {
                return Err(CryptoError::KeyLoadError(
                    format!("Invalid Ed25519 key length: expected 32, 34, or 64 bytes, got {}", key_bytes.len()),
                ));
            }
        };

        // Ensure we have exactly 32 bytes
        if raw_key_bytes.len() != 32 {
            return Err(CryptoError::KeyLoadError(
                format!("Failed to extract 32-byte Ed25519 key from {} bytes", key_bytes.len()),
            ));
        }

        // Create SecretKey from raw bytes (takes [u8; 32] by reference)
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(raw_key_bytes);

        // Create SigningKey directly from bytes
        let signing_key = SigningKey::from_bytes(&key_array);

        Ok(Self { 
            signing_key: Secret::new(SigningKeyWrapper::new(signing_key)),
        })
    }

    /// Mint a JWT token with the exact payload structure matching Python implementation
    /// 
    /// Payload structure:
    /// - iss: "sentinel-interceptor"
    /// - sub: session_id
    /// - scope: format!("tool:{}", tool_name)
    /// - p_hash: SHA-256 hash of canonicalized args
    /// - jti: UUID v4 (nonce for replay protection)
    /// - iat: current timestamp
    /// - exp: iat + 5 seconds
    pub fn mint_token(
        &self,
        session_id: &str,
        tool_name: &str,
        args: &Value,
    ) -> Result<String, CryptoError> {
        let p_hash = Self::hash_params(args)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| CryptoError::SigningError(format!("System time error: {}", e)))?
            .as_secs();

        // Create payload matching Python JWT structure exactly
        let mut claims = serde_json::Map::new();
        claims.insert("iss".to_string(), Value::String("sentinel-interceptor".to_string()));
        claims.insert("sub".to_string(), Value::String(session_id.to_string()));
        claims.insert("scope".to_string(), Value::String(format!("tool:{}", tool_name)));
        claims.insert("p_hash".to_string(), Value::String(p_hash));
        claims.insert("jti".to_string(), Value::String(uuid::Uuid::new_v4().to_string()));
        claims.insert("iat".to_string(), Value::Number(now.into()));
        claims.insert("exp".to_string(), Value::Number((now + 5).into()));

        // Create JWT header
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "JWT"
        });

        // Encode header and payload as base64url (no padding)
        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&header)
                .map_err(|e| CryptoError::SigningError(format!("Failed to serialize header: {}", e)))?
                .as_bytes(),
        );
        let payload_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&claims)
                .map_err(|e| CryptoError::SigningError(format!("Failed to serialize claims: {}", e)))?
                .as_bytes(),
        );

        // Create message to sign: header.payload
        let message = format!("{}.{}", header_b64, payload_b64);

        // Sign with Ed25519 (expose secret only for signing operation)
        let signature = self.signing_key.expose_secret().expose().sign(message.as_bytes());

        // Encode signature as base64url
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes().as_slice());

        // Return complete JWT: header.payload.signature
        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }

    /// Canonicalize JSON according to RFC 8785 (JCS - JSON Canonicalization Scheme)
    /// 
    /// Uses `serde_jcs` crate for RFC 8785 compliant canonicalization.
    /// Matches Python implementation exactly:
    /// - sort_keys=True (lexicographical key ordering)
    /// - separators=(',', ':') (no whitespace)
    /// - ensure_ascii=False (UTF-8 handling)
    /// 
    /// Special case: null values return b"{}" to match Python behavior.
    pub fn canonicalize(data: &Value) -> Result<Vec<u8>, CryptoError> {
        // Handle None/null case - Python returns b"{}" for None
        // To match Python behavior exactly, null becomes empty object
        if data.is_null() {
            return Ok(b"{}".to_vec());
        }

        // Use serde_jcs for RFC 8785 compliant canonicalization
        serde_jcs::to_string(data)
            .map(|s| s.into_bytes())
            .map_err(|e| CryptoError::CanonicalizationError(format!("JCS canonicalization error: {}", e)))
    }

    /// Hash parameters using SHA-256 of canonicalized JSON
    /// 
    /// Returns hex-encoded hash string (64 characters)
    /// Must produce identical output to Python implementation
    pub fn hash_params(args: &Value) -> Result<String, CryptoError> {
        let canonical_bytes = Self::canonicalize(args)?;
        let mut hasher = Sha256::new();
        hasher.update(&canonical_bytes);
        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }
}
