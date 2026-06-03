# Lilith Zero: CLI Hook (claude) Latency Benchmark Report

## Execution Summary
- **Total Invocations**: 1000
- **Correct Decisions**: 1000
- **Mismatches**: 0
- **Policy Enforcement Accuracy**: 100.00%
- **Total Benchmark Duration**: 4.736s
- **Status**: ✓ PASS

## Latency Metrics Breakdown (ms)

| Metric Phase            | Avg (ms) | Med (ms) | P95 (ms) | P99 (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 0.03 | 0.03 | 0.05 | 0.06 | 0.07 |
| Session State Load | 0.01 | 0.01 | 0.02 | 0.03 | 0.05 |
| Security Policy Eval | 0.87 | 0.84 | 0.98 | 1.15 | 1.69 |
| Session State Save | 0.02 | 0.02 | 0.03 | 0.04 | 0.06 |
| Binary Startup/IO Overhead | 3.75 | 3.72 | 3.98 | 4.45 | 5.67 |
| Total Process Execution | 4.69 | 4.64 | 4.99 | 5.63 | 6.93 |
