// Performance benchmarks for policy evaluation

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinel_interceptor::core::models::{PolicyDefinition, PolicyRule};
use sentinel_interceptor::engine::evaluator::PolicyEvaluator;
use std::collections::{HashMap, HashSet};

fn bench_policy_evaluation(c: &mut Criterion) {
    // Create test policy
    let mut static_rules = HashMap::new();
    static_rules.insert("read_file".to_string(), "ALLOW".to_string());
    static_rules.insert("write_file".to_string(), "DENY".to_string());
    
    let policy = PolicyDefinition {
        name: "test_policy".to_string(),
        static_rules,
        taint_rules: vec![],
    };
    
    c.bench_function("policy_evaluation_static_allow", |b| {
        b.iter(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(PolicyEvaluator::evaluate(
                black_box(&policy),
                black_box("read_file"),
                black_box(&[]),
                black_box(&[]),
                black_box(&HashSet::new()),
            )).unwrap();
        });
    });
    
    c.bench_function("policy_evaluation_static_deny", |b| {
        b.iter(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(PolicyEvaluator::evaluate(
                black_box(&policy),
                black_box("write_file"),
                black_box(&[]),
                black_box(&[]),
                black_box(&HashSet::new()),
            )).unwrap();
        });
    });
}

criterion_group!(benches, bench_policy_evaluation);
criterion_main!(benches);

