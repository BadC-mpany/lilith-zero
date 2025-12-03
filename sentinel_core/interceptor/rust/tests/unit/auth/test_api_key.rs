// Unit tests for API key hashing and validation

use sentinel_interceptor::auth::api_key::{ApiKey, ApiKeyHash};

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
fn test_api_key_hash_hex_format() {
    let hash = ApiKeyHash::from_api_key("test_key");
    let hash_str = hash.as_str();
    
    // Verify it's valid hex
    assert!(hash_str.chars().all(|c| c.is_ascii_hexdigit()), 
            "Hash should contain only hex characters");
}

#[test]
fn test_api_key_redaction_debug() {
    let api_key = ApiKey::from_str("secret_key_123");
    let debug_str = format!("{:?}", api_key);
    
    assert!(!debug_str.contains("secret_key_123"), "Debug should not expose key");
    assert!(debug_str.contains("REDACTED") || debug_str.contains("<REDACTED>"), 
            "Debug should contain redaction marker");
}

#[test]
fn test_api_key_redaction_display() {
    let api_key = ApiKey::from_str("secret_key_123");
    let display_str = format!("{}", api_key);
    
    assert!(!display_str.contains("secret_key_123"), "Display should not expose key");
    assert!(display_str.contains("REDACTED") || display_str.contains("<REDACTED>"), 
            "Display should contain redaction marker");
}

#[test]
fn test_api_key_hash_method() {
    let api_key = ApiKey::from_str("test_key");
    let hash = api_key.hash();
    
    assert_eq!(hash.as_str().len(), 64, "Hash should be 64 characters");
    
    // Verify hash matches direct hashing
    let direct_hash = ApiKeyHash::from_api_key("test_key");
    assert_eq!(hash, direct_hash, "ApiKey::hash() should match direct hashing");
}

#[test]
fn test_api_key_expose_secret() {
    let original_key = "test_secret_key";
    let api_key = ApiKey::from_str(original_key);
    let exposed = api_key.expose_secret();
    
    assert_eq!(exposed, original_key, "Expose secret should return original key");
}

#[test]
fn test_api_key_hash_case_sensitive() {
    let key1 = "TestKey";
    let key2 = "testkey";
    let hash1 = ApiKeyHash::from_api_key(key1);
    let hash2 = ApiKeyHash::from_api_key(key2);
    
    assert_ne!(hash1, hash2, "Hash should be case-sensitive");
}

#[test]
fn test_api_key_hash_empty_key() {
    let hash = ApiKeyHash::from_api_key("");
    assert_eq!(hash.as_str().len(), 64, "Empty key should still produce 64-char hash");
}

#[test]
fn test_api_key_hash_unicode() {
    let key = "test_key_🚀_unicode";
    let hash = ApiKeyHash::from_api_key(key);
    assert_eq!(hash.as_str().len(), 64, "Unicode key should produce valid hash");
}

