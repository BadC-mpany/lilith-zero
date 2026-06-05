# Lilith Zero: CLI Hook (copilot) Latency Benchmark Report

## Execution Summary
- **Total Invocations**: 1000
- **Concurrency (VUs)**: 10000
- **Correct Decisions**: 1000
- **Mismatches**: 0
- **Policy Enforcement Accuracy**: 100.00%
- **Total Benchmark Duration**: 2.262s
- **Status**: ✓ PASS

## Latency Metrics Breakdown (ms)

| Metric Phase            | Avg (ms) | Med (ms) | P95 (ms) | P99 (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 0.17 | 0.04 | 0.09 | 4.16 | 11.66 |
| Session State Load | 0.03 | 0.01 | 0.03 | 0.09 | 3.93 |
| Security Policy Eval | 2.83 | 1.63 | 8.56 | 13.32 | 19.22 |
| Session State Save | 0.04 | 0.03 | 0.04 | 0.15 | 3.68 |
| Binary Startup/IO Overhead | 77.86 | 63.14 | 192.74 | 272.49 | 375.80 |
| Total Process Execution | 80.92 | 66.59 | 198.00 | 274.12 | 377.21 |
