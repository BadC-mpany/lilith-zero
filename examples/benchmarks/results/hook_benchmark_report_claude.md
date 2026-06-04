# Lilith Zero: CLI Hook (claude) Latency Benchmark Report

## Execution Summary
- **Total Invocations**: 10000
- **Concurrency (VUs)**: 100
- **Correct Decisions**: 10000
- **Mismatches**: 0
- **Policy Enforcement Accuracy**: 100.00%
- **Total Benchmark Duration**: 22.773s
- **Status**: ✓ PASS

## Latency Metrics Breakdown (ms)

| Metric Phase            | Avg (ms) | Med (ms) | P95 (ms) | P99 (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 0.12 | 0.04 | 0.07 | 2.23 | 34.09 |
| Session State Load | 0.03 | 0.02 | 0.03 | 0.12 | 12.15 |
| Security Policy Eval | 2.90 | 1.65 | 8.06 | 16.22 | 58.24 |
| Session State Save | 0.04 | 0.03 | 0.04 | 0.23 | 10.07 |
| Binary Startup/IO Overhead | 202.77 | 172.94 | 480.54 | 672.62 | 1453.80 |
| Total Process Execution | 205.87 | 175.83 | 483.57 | 676.68 | 1459.05 |
