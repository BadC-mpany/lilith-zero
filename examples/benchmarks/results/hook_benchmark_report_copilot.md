# Lilith Zero: CLI Hook (copilot) Latency Benchmark Report

## Execution Summary
- **Total Invocations**: 10000
- **Concurrency (VUs)**: 100
- **Correct Decisions**: 10000
- **Mismatches**: 0
- **Policy Enforcement Accuracy**: 100.00%
- **Total Benchmark Duration**: 37.789s
- **Status**: ✓ PASS

## Latency Metrics Breakdown (ms)

| Metric Phase            | Avg (ms) | Med (ms) | P95 (ms) | P99 (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 352.03 | 376.61 | 623.79 | 776.56 | 1105.19 |
| Session State Load | 1.23 | 1.22 | 2.37 | 2.84 | 6.15 |
| Security Policy Eval | 1.32 | 1.24 | 2.15 | 3.34 | 7.44 |
| Session State Save | 1.14 | 1.13 | 2.27 | 2.81 | 5.65 |
| Binary Startup/IO Overhead | 11.58 | 5.77 | 49.07 | 118.85 | 327.18 |
| Total Process Execution | 367.30 | 386.58 | 634.09 | 787.17 | 1116.37 |
