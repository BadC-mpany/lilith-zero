# Lilith Zero: CLI Hook (claude) Latency Benchmark Report

## Execution Summary
- **Total Invocations**: 1000
- **Concurrency (VUs)**: 10000
- **Correct Decisions**: 1000
- **Mismatches**: 0
- **Policy Enforcement Accuracy**: 100.00%
- **Total Benchmark Duration**: 2.200s
- **Status**: ✓ PASS

## Latency Metrics Breakdown (ms)

| Metric Phase            | Avg (ms) | Med (ms) | P95 (ms) | P99 (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 0.20 | 0.04 | 0.15 | 5.38 | 21.23 |
| Session State Load | 0.03 | 0.02 | 0.03 | 0.11 | 2.49 |
| Security Policy Eval | 2.69 | 1.69 | 7.06 | 11.34 | 19.98 |
| Session State Save | 0.05 | 0.03 | 0.04 | 0.60 | 5.27 |
| Binary Startup/IO Overhead | 76.57 | 64.99 | 180.31 | 241.51 | 397.68 |
| Total Process Execution | 79.54 | 67.69 | 185.15 | 245.74 | 407.29 |
