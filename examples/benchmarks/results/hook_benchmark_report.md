# Lilith Zero: CLI Hook Latency Benchmark Report

## Execution Summary
- **Total Invocations**: 100
- **Correct Decisions**: 100
- **Mismatches**: 0
- **Policy Enforcement Accuracy**: 100.00%
- **Total Benchmark Duration**: 0.567s
- **Status**: ✓ PASS

## Latency Metrics Breakdown (ms)

| Metric Phase            | Avg (ms) | Med (ms) | P95 (ms) | P99 (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 0.04 | 0.04 | 0.06 | 0.06 | 0.48 |
| Session State Load | 0.02 | 0.01 | 0.02 | 0.04 | 0.09 |
| Security Policy Eval | 1.05 | 0.99 | 1.44 | 1.62 | 1.73 |
| Session State Save | 0.03 | 0.03 | 0.03 | 0.04 | 0.04 |
| Binary Startup/IO Overhead | 4.48 | 4.34 | 5.48 | 6.11 | 6.29 |
| Total Process Execution | 5.61 | 5.46 | 6.98 | 7.60 | 7.83 |
