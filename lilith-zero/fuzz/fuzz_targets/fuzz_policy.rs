// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use lilith_zero::engine::PolicyEngine;
use lilith_zero::config::Config;
use lilith_zero::engine_core::models::JsonRpcRequest;
use serde_json;

fuzz_target!(|data: &[u8]| {
    // Fuzz the Policy Engine
    // We construct a random policy (if possible) or use a static one,
    // and then fuzz the requests against it.
    
    // For now, let's use a permissive policy to test the engine's checking logic robustness
    // We could also try to deserialize `data` into a Policy object, but that might fail too often.
    // Better to fuzz the `check_request` method with arbitrary inputs.

    let config = Config::default(); // Default config
    // In a real fuzzer, we might want to populate this config with random rules from `data`
    
    let engine = PolicyEngine::new(config);
    
    // Interpret data as a JSON-RPC request if possible
    if let Ok(request) = serde_json::from_slice::<JsonRpcRequest>(data) {
        // We don't care about the result, just that it doesn't panic
        let _ = engine.check_request(&request);
    } else {
        // If not valid JSON, we can still construct a synthetic request from bytes
        // to test specific fields if we wanted, but `check_request` takes a typed JsonRpcRequest.
        // So standard JSON fuzzing coverage is good here.
    }
});
