use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lilith_zero::mcp::codec::McpCodec;
use lilith_zero::utils::policy_validator::PolicyValidator;
use lilith_zero::engine_core::models::{PolicyDefinition, PolicyRule};
use std::collections::HashMap;
use tokio_util::codec::Decoder;
use bytes::BytesMut;

fn bench_codec_decode(c: &mut Criterion) {
    let mut codec = McpCodec::new();
    let data = b"Content-Length: 43\r\n\r\n{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}";
    
    c.bench_function("codec_decode_ping", |b| {
        b.iter(|| {
            let mut src = BytesMut::from(&data[..]);
            let _ = codec.decode(black_box(&mut src));
        })
    });
}

fn bench_policy_validator(c: &mut Criterion) {
    let rule = PolicyRule {
        tool: Some("test_tool".to_string()),
        tool_class: None,
        action: "ALLOW".to_string(),
        tag: None,
        forbidden_tags: None,
        required_taints: None,
        error: None,
        pattern: None,
        exceptions: None,
    };
    
    let policy = PolicyDefinition {
        id: "bench-policy".to_string(),
        customer_id: "bench".to_string(),
        name: "Benchmark Policy".to_string(),
        version: 1,
        static_rules: HashMap::new(),
        resource_rules: Vec::new(),
        taint_rules: vec![rule],
        created_at: None,
        protect_lethal_trifecta: false,
    };

    c.bench_function("policy_validation_single", |b| {
        b.iter(|| {
            let _ = PolicyValidator::validate_policies(black_box(std::slice::from_ref(&policy)));
        })
    });
}

criterion_group!(benches, bench_codec_decode, bench_policy_validator);
criterion_main!(benches);
