use bytes::BytesMut;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use lilith_zero::engine_core::models::{PolicyDefinition, PolicyRule};
use lilith_zero::mcp::codec::McpCodec;
use lilith_zero::server::policy_store::PolicyStore;
use lilith_zero::utils::policy_validator::PolicyValidator;
use std::collections::HashMap;
use std::io::Write as _;
use std::str::FromStr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio_util::codec::Decoder;

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Policy validator
// ---------------------------------------------------------------------------

fn bench_policy_validator(c: &mut Criterion) {
    let rule = PolicyRule {
        tool: Some("test_tool".to_string()),
        tool_class: None,
        action: "ALLOW".to_string(),
        tag: None,
        forbidden_tags: None,
        required_taints: None,
        error: None,
        match_args: None,
        pattern: None,
        exceptions: None,
    };

    let policy = PolicyDefinition {
        id: "bench-policy".to_string(),
        customer_id: "bench".to_string(),
        name: "Benchmark Policy".to_string(),
        description: None,
        schema_version: None,
        version: 1,
        static_rules: HashMap::new(),
        resource_rules: Vec::new(),
        taint_rules: vec![rule],
        created_at: None,
        protect_lethal_trifecta: false,
        tool_classes: Default::default(),
        rate_limit: None,
        replay_window_secs: 0,
        pin_mode: None,
    };

    c.bench_function("policy_validation_single", |b| {
        b.iter(|| {
            let _ = PolicyValidator::validate_policies(black_box(std::slice::from_ref(&policy)));
        })
    });
}

// ---------------------------------------------------------------------------
// PolicyStore — latency micro-benchmarks
//
// These measure the overhead of the hot path (get) and the reload path.
// The <1 s e2e budget is dominated by network; these should all be <1 ms.
// ---------------------------------------------------------------------------

const SAMPLE_CEDAR: &str = r#"
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"my-tool"
};
"#;

/// `PolicyStore::get` — the per-request hot path.
///
/// This is an uncontested async RwLock read + HashMap lookup.
/// Expected: 100–500 ns. Any result >1 ms would be alarming.
fn bench_policy_store_get(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let store = rt.block_on(async {
        let mut map = HashMap::new();
        let ps = cedar_policy::PolicySet::from_str(SAMPLE_CEDAR).unwrap();
        map.insert("test-agent".to_string(), Arc::new(ps));
        PolicyStore::from_map(map, None, None, false)
    });

    c.bench_function("policy_store_get_hit", |b| {
        b.iter(|| {
            rt.block_on(async { store.get(black_box("test-agent")).await })
        })
    });

    c.bench_function("policy_store_get_miss", |b| {
        b.iter(|| {
            rt.block_on(async { store.get(black_box("unknown-agent")).await })
        })
    });
}

/// `PolicyStore::reload` — full disk-read + parse + atomic swap.
///
/// Parsing happens outside the write lock; the lock is held for microseconds.
/// Expected: 1–20 ms for a small number of policies.
fn bench_policy_store_reload(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();

    // Write varying numbers of Cedar policy files
    for agent_count in [1_usize, 5, 10] {
        for i in 0..agent_count {
            let path = dir.join(format!("agent-{i}.cedar"));
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(SAMPLE_CEDAR.as_bytes()).unwrap();
        }
    }

    let store = rt.block_on(PolicyStore::load_from_dir(dir.clone(), false)).unwrap();

    c.bench_function("policy_store_reload_10_policies", |b| {
        b.iter(|| rt.block_on(async { store.reload().await.unwrap() }))
    });
}

/// `PolicyStore::reload` with varying policy counts — measures parse scaling.
fn bench_policy_store_reload_scaling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("policy_store_reload_scaling");

    for policy_count in [1_usize, 5, 20] {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        for i in 0..policy_count {
            let path = dir.join(format!("agent-{i}.cedar"));
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(SAMPLE_CEDAR.as_bytes()).unwrap();
        }

        let store = rt
            .block_on(PolicyStore::load_from_dir(dir.clone(), false))
            .unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(policy_count),
            &policy_count,
            |b, _| b.iter(|| rt.block_on(async { store.reload().await.unwrap() })),
        );
    }
    group.finish();
}

/// Concurrent `PolicyStore::get` — simulates N readers hitting the store simultaneously.
///
/// This validates that the RwLock doesn't become a bottleneck under concurrency.
fn bench_policy_store_concurrent_get(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let store = {
        let mut map = HashMap::new();
        let ps = cedar_policy::PolicySet::from_str(SAMPLE_CEDAR).unwrap();
        map.insert("agent-1".to_string(), Arc::new(ps));
        Arc::new(PolicyStore::from_map(map, None, None, false))
    };

    let mut group = c.benchmark_group("policy_store_concurrent_get");

    for thread_count in [1_usize, 4, 8, 16] {
        group.bench_with_input(
            BenchmarkId::from_parameter(thread_count),
            &thread_count,
            |b, &n| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(n);
                        for _ in 0..n {
                            let s = store.clone();
                            handles.push(tokio::spawn(async move { s.get("agent-1").await }));
                        }
                        for h in handles {
                            let _ = h.await.unwrap();
                        }
                    })
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_codec_decode,
    bench_policy_validator,
    bench_policy_store_get,
    bench_policy_store_reload,
    bench_policy_store_reload_scaling,
    bench_policy_store_concurrent_get,
);
criterion_main!(benches);
