// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use lilith_zero::mcp::codec::McpCodec;
use tokio_util::codec::Decoder;
use bytes::BytesMut;

fuzz_target!(|data: &[u8]| {
    // Fuzz the codec decoding logic
    // We want to ensure that NO sequence of bytes causes a panic.
    // We don't necessarily care about the logic correctness here (that is for unit tests),
    // but we care about robustness against crashes (unwraps, out of bounds, etc).
    
    let mut codec = McpCodec::new();
    let mut buffer = BytesMut::from(data);
    
    // The decode method should return Ok(Some), Ok(None), or Err.
    // It should NEVER panic.
    let _ = codec.decode(&mut buffer);
});
