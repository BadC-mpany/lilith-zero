// Performance benchmarks for cryptographic operations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinel_interceptor::core::crypto::CryptoSigner;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::json;

fn bench_crypto_signing(c: &mut Criterion) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let signer = CryptoSigner::from_signing_key(signing_key);
    
    let session_id = "test-session-123";
    let tool_name = "read_file";
    let args = json!({"path": "/tmp/test.txt"});
    
    c.bench_function("crypto_signing", |b| {
        b.iter(|| {
            signer.mint_token(
                black_box(session_id),
                black_box(tool_name),
                black_box(&args),
            ).unwrap();
        });
    });
}

fn bench_json_canonicalization(c: &mut Criterion) {
    let data = json!({
        "b": 2,
        "a": 1,
        "nested": {
            "z": 3,
            "y": 2
        }
    });
    
    c.bench_function("json_canonicalization", |b| {
        b.iter(|| {
            CryptoSigner::canonicalize(black_box(&data)).unwrap();
        });
    });
}

criterion_group!(benches, bench_crypto_signing, bench_json_canonicalization);
criterion_main!(benches);


