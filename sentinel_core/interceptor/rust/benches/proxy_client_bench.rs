// Performance benchmarks for proxy client

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinel_interceptor::proxy::ProxyClientImpl;
use serde_json::json;
use std::time::Duration;

fn bench_proxy_client_creation(c: &mut Criterion) {
    c.bench_function("proxy_client_creation", |b| {
        b.iter(|| {
            black_box(ProxyClientImpl::new(5).unwrap());
        });
    });
}

fn bench_jsonrpc_request_construction(c: &mut Criterion) {
    let client = ProxyClientImpl::new(5).unwrap();
    
    c.bench_function("jsonrpc_request_construction", |b| {
        b.iter(|| {
            // Simulate request construction overhead
            let _request = json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "test_tool",
                    "arguments": {"arg": "value"},
                    "session_id": "test_session",
                    "agent_callback_url": null
                },
                "id": "test-id"
            });
            black_box(_request);
        });
    });
}

fn bench_error_mapping(c: &mut Criterion) {
    use sentinel_interceptor::proxy::client::JsonRpcError;
    
    let error = JsonRpcError {
        code: -32600,
        message: "Invalid request format".to_string(),
        data: None,
    };
    
    c.bench_function("jsonrpc_error_mapping", |b| {
        b.iter(|| {
            black_box(ProxyClientImpl::map_jsonrpc_error(&error));
        });
    });
}

fn bench_response_parsing(c: &mut Criterion) {
    use sentinel_interceptor::proxy::client::JsonRpcResponse;
    
    let response_json = json!({
        "jsonrpc": "2.0",
        "result": {
            "status": "success",
            "data": "test_result",
            "nested": {
                "field1": "value1",
                "field2": 123,
                "field3": [1, 2, 3, 4, 5]
            }
        },
        "id": "test-id"
    });
    
    c.bench_function("jsonrpc_response_parsing", |b| {
        b.iter(|| {
            let response: JsonRpcResponse = serde_json::from_value(response_json.clone()).unwrap();
            black_box(response);
        });
    });
}

criterion_group! {
    name = proxy_client_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(100);
    targets = bench_proxy_client_creation, bench_jsonrpc_request_construction, bench_error_mapping, bench_response_parsing
}

criterion_main!(proxy_client_benches);

