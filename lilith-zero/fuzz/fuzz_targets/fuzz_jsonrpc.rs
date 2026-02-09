// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use lilith_zero::engine_core::models::{JsonRpcRequest, JsonRpcResponse};
use serde_json;

fuzz_target!(|data: &[u8]| {
    // Fuzz the JSON-RPC deserialization layers
    // We want to ensure that weird JSON structures don't cause crashes in our typed structs.
    // Specially important for `params` which can be Any.

    // Try parsing as Request
    let _ = serde_json::from_slice::<JsonRpcRequest>(data);
    
    // Try parsing as Response
    let _ = serde_json::from_slice::<JsonRpcResponse>(data);
});
