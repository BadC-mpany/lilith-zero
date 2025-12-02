// Unit tests for crypto operations

use sentinel_interceptor::core::crypto::CryptoSigner;
use serde_json::{json, Value};

#[test]
fn test_canonicalize_deterministic() {
    // Test that same data produces same canonical output regardless of key order
    let data1 = json!({"b": 2, "a": 1});
    let data2 = json!({"a": 1, "b": 2});

    let canonical1 = CryptoSigner::canonicalize(&data1).unwrap();
    let canonical2 = CryptoSigner::canonicalize(&data2).unwrap();

    assert_eq!(canonical1, canonical2);
    // Should be sorted: {"a":1,"b":2}
    let canonical_str = String::from_utf8(canonical1).unwrap();
    assert_eq!(canonical_str, r#"{"a":1,"b":2}"#);
}

#[test]
fn test_canonicalize_nested_objects() {
    // Test nested object key sorting
    let data = json!({
        "z": {"b": 2, "a": 1},
        "a": "value"
    });

    let canonical = CryptoSigner::canonicalize(&data).unwrap();
    let canonical_str = String::from_utf8(canonical).unwrap();
    
    // Should sort keys at all levels
    assert!(canonical_str.starts_with(r#"{"a":"value","z":{"#));
    assert!(canonical_str.contains(r#"{"a":1,"b":2}"#));
}

#[test]
fn test_canonicalize_arrays() {
    // Arrays should preserve order
    let data = json!({
        "items": [3, 1, 2],
        "name": "test"
    });

    let canonical = CryptoSigner::canonicalize(&data).unwrap();
    let canonical_str = String::from_utf8(canonical).unwrap();
    
    // Keys sorted, but array order preserved
    assert!(canonical_str.contains(r#""items":[3,1,2]"#));
}

#[test]
fn test_canonicalize_null() {
    let data = Value::Null;
    let canonical = CryptoSigner::canonicalize(&data).unwrap();
    assert_eq!(canonical, b"{}");
}

#[test]
fn test_canonicalize_empty_object() {
    let data = json!({});
    let canonical = CryptoSigner::canonicalize(&data).unwrap();
    assert_eq!(canonical, b"{}");
}

#[test]
fn test_canonicalize_utf8() {
    // Test UTF-8 handling (ensure_ascii=False)
    let data = json!({"text": "café", "emoji": "🚀"});
    let canonical = CryptoSigner::canonicalize(&data).unwrap();
    let canonical_str = String::from_utf8(canonical).unwrap();
    
    // Should not escape UTF-8 characters
    assert!(canonical_str.contains("café"));
    assert!(canonical_str.contains("🚀"));
}

#[test]
fn test_hash_params_deterministic() {
    // Test that hash_params produces same output for same input
    let args1 = json!({"b": 2, "a": 1});
    let args2 = json!({"a": 1, "b": 2});

    let hash1 = CryptoSigner::hash_params(&args1).unwrap();
    let hash2 = CryptoSigner::hash_params(&args2).unwrap();

    assert_eq!(hash1, hash2);
    assert_eq!(hash1.len(), 64); // SHA-256 hex is 64 characters
}

#[test]
fn test_hash_params_empty() {
    let args = json!({});
    let hash = CryptoSigner::hash_params(&args).unwrap();
    assert_eq!(hash.len(), 64);
    
    // Empty object should produce consistent hash
    let hash2 = CryptoSigner::hash_params(&json!({})).unwrap();
    assert_eq!(hash, hash2);
}

#[test]
fn test_hash_params_different_inputs() {
    // Different inputs should produce different hashes
    let args1 = json!({"a": 1});
    let args2 = json!({"a": 2});
    let args3 = json!({"b": 1});

    let hash1 = CryptoSigner::hash_params(&args1).unwrap();
    let hash2 = CryptoSigner::hash_params(&args2).unwrap();
    let hash3 = CryptoSigner::hash_params(&args3).unwrap();

    assert_ne!(hash1, hash2);
    assert_ne!(hash1, hash3);
    assert_ne!(hash2, hash3);
}

#[test]
fn test_hash_params_complex() {
    // Test with complex nested structures
    let args = json!({
        "tool": "read_file",
        "params": {
            "path": "/tmp/file.txt",
            "encoding": "utf-8"
        },
        "metadata": {
            "session": "abc123",
            "timestamp": 1234567890
        }
    });

    let hash = CryptoSigner::hash_params(&args).unwrap();
    assert_eq!(hash.len(), 64);
    
    // Should be deterministic
    let hash2 = CryptoSigner::hash_params(&args).unwrap();
    assert_eq!(hash, hash2);
}

#[test]
fn test_hash_params_utf8() {
    // Test UTF-8 handling in hash_params
    let args = json!({"text": "café", "name": "José"});
    let hash = CryptoSigner::hash_params(&args).unwrap();
    assert_eq!(hash.len(), 64);
    
    // Should produce same hash regardless of key order
    let args2 = json!({"name": "José", "text": "café"});
    let hash2 = CryptoSigner::hash_params(&args2).unwrap();
    assert_eq!(hash, hash2);
}

#[test]
fn test_hash_params_numeric_types() {
    // Test that numeric types are handled correctly
    let args1 = json!({"count": 42});
    let args2 = json!({"count": 42.0});
    
    // Integers and floats should be different in JSON
    let hash1 = CryptoSigner::hash_params(&args1).unwrap();
    let hash2 = CryptoSigner::hash_params(&args2).unwrap();
    
    // These should be different because JSON distinguishes int from float
    assert_ne!(hash1, hash2);
}

#[test]
fn test_canonicalize_boolean() {
    // Test boolean values
    let data = json!({"enabled": true, "disabled": false});
    let canonical = CryptoSigner::canonicalize(&data).unwrap();
    let canonical_str = String::from_utf8(canonical).unwrap();
    
    assert!(canonical_str.contains(r#""disabled":false"#));
    assert!(canonical_str.contains(r#""enabled":true"#));
}

#[test]
fn test_canonicalize_numbers() {
    // Test various number formats
    let data = json!({
        "int": 42,
        "float": 3.14,
        "negative": -10,
        "zero": 0
    });
    
    let canonical = CryptoSigner::canonicalize(&data).unwrap();
    let canonical_str = String::from_utf8(canonical).unwrap();
    
    // Should contain all numbers
    assert!(canonical_str.contains(r#""int":42"#));
    assert!(canonical_str.contains(r#""float":3.14"#));
    assert!(canonical_str.contains(r#""negative":-10"#));
    assert!(canonical_str.contains(r#""zero":0"#));
}

// Note: mint_token tests require a valid PEM file, so we'll skip those in unit tests
// Integration tests should verify JWT token creation and verification

