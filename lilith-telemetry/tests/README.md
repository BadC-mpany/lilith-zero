# Telemetry Test Suite

This directory contains separate executables for integration and stress tests of the `lilith-telemetry` framework. The tests exhaustively validate the underlying lock-free architecture, zero-cost macro definitions, context propagation, and remote API behaviors mirroring Jaeger workflows across all three deployment modes (`Alone`, `FlockMember`, and `FlockHead`).

## What it Does

Since the internal `DISPATCHER` is a global `OnceLock` singleton, we enforce complete memory isolation per test file. Cargo compiles these independently:

- **`test_mode_alone.rs`**: Tests isolated "development" mode logic. Bootstraps the telemetry engine natively, validates OTel context propagation (TraceID/SpanID) via nested spans, pushes Critical Fast-Path traces (100% sampling), and exhausts 10,000 looping iterations of Routine Slow-Path traces to validate Adaptive Sampling blocks without network binding.
- **`test_mode_member.rs`**: Simulates Jaeger `Agent` streaming. Assigns TPM identity context to the dispatcher, binds it to a loopback collector via non-blocking UDP sockets, generates tracing streams under backpressure, and physically captures the emitted networking frames verifying proper encryption layers.
- **`test_mode_head.rs`**: Validates the Jaeger `Collector/Ingester` architecture natively. Spawns the unified API receiver, injects a series of authenticated datagrams via independent streams, and verifies that the standalone thread loop accepts and mitigates intense high-throughput tracing streams synchronously.

## Running the Tests

To run the full suite using Cargo:

```bash
cargo test --test '*'
```

### Options & Flags

If you want to read console outputs explicitly (like "Telemetry Flow Exhaustive Test Passed!") or debug failures, attach the `nocapture` flag:

```bash
cargo test --test '*' -- --nocapture
```

You can isolate specific architectural test components natively:

```bash
# Isolate just the UDP API Receiver Ingestion logic checks:
cargo test --test test_mode_head -- --nocapture

# Isolate just the lock-free Ring Buffer & Context propagation testing:
cargo test --test test_mode_alone -- --nocapture
```
