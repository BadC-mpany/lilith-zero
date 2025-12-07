// API key hashing and validation

use hex;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use std::fmt;

/// API key hash - SHA-256 hash of API key (64-character hex string)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApiKeyHash(String);

impl ApiKeyHash {
    /// Create an ApiKeyHash from a plaintext API key
    /// 
    /// Uses SHA-256 hashing to prevent timing attacks during lookup.
    /// The hash is deterministic: same API key always produces same hash.
    pub fn from_api_key(api_key: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        let hash_bytes = hasher.finalize();
        Self(hex::encode(hash_bytes))
    }

    /// Create an ApiKeyHash from an existing hash string (64 hex characters)
    /// 
    /// Use this when you already have a hash and don't want to hash again.
    /// Validates that the string is 64 hex characters.
    pub fn from_hash_string(hash_str: &str) -> Result<Self, String> {
        if hash_str.len() != 64 {
            return Err(format!("Invalid hash length: expected 64, got {}", hash_str.len()));
        }
        // Validate hex characters
        if !hash_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Invalid hash format: must be 64 hex characters".to_string());
        }
        Ok(Self(hash_str.to_string()))
    }

    /// Get the hash as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApiKeyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// API key wrapper with memory protection
/// 
/// Uses `secrecy::Secret` to prevent accidental logging or memory swapping
/// of sensitive API key material.
pub struct ApiKey(Secret<String>);

impl ApiKey {
    /// Create a new ApiKey from a string
    pub fn new(api_key: &str) -> Self {
        Self(Secret::new(api_key.to_string()))
    }

    /// Hash the API key to produce an ApiKeyHash
    pub fn hash(&self) -> ApiKeyHash {
        ApiKeyHash::from_api_key(self.expose_secret())
    }

    /// Expose the secret API key (use with caution)
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("key", &"<REDACTED>")
            .finish()
    }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<REDACTED>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_hash_deterministic() {
        let key1 = "test_api_key_123";
        let hash1 = ApiKeyHash::from_api_key(key1);
        let hash2 = ApiKeyHash::from_api_key(key1);
        
        assert_eq!(hash1, hash2, "Same API key should produce same hash");
    }

    #[test]
    fn test_api_key_hash_different_keys() {
        let key1 = "test_api_key_123";
        let key2 = "test_api_key_456";
        let hash1 = ApiKeyHash::from_api_key(key1);
        let hash2 = ApiKeyHash::from_api_key(key2);
        
        assert_ne!(hash1, hash2, "Different API keys should produce different hashes");
    }

    #[test]
    fn test_api_key_hash_length() {
        let hash = ApiKeyHash::from_api_key("test_key");
        assert_eq!(hash.as_str().len(), 64, "SHA-256 hash should be 64 hex characters");
    }

    #[test]
    fn test_api_key_redaction() {
        let api_key = ApiKey::new("secret_key_123");
        let debug_str = format!("{:?}", api_key);
        let display_str = format!("{}", api_key);
        
        assert!(!debug_str.contains("secret_key_123"), "Debug should not expose key");
        assert!(!display_str.contains("secret_key_123"), "Display should not expose key");
        assert!(debug_str.contains("REDACTED") || debug_str.contains("<REDACTED>"));
    }

    #[test]
    fn test_api_key_hash_method() {
        let api_key = ApiKey::new("test_key");
        let hash = api_key.hash();
        
        assert_eq!(hash.as_str().len(), 64, "Hash should be 64 characters");
        
        // Verify hash matches direct hashing
        let direct_hash = ApiKeyHash::from_api_key("test_key");
        assert_eq!(hash, direct_hash, "ApiKey::hash() should match direct hashing");
    }
}
