# Lilith Zero: CLI Hook (copilot) Latency Benchmark Report

## Execution Summary
- **Total Invocations**: 1000
- **Correct Decisions**: 1000
- **Mismatches**: 0
- **Policy Enforcement Accuracy**: 100.00%
- **Total Benchmark Duration**: 5.036s
- **Status**: ✓ PASS

## Latency Metrics Breakdown (ms)

| Metric Phase            | Avg (ms) | Med (ms) | P95 (ms) | P99 (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 0.02 | 0.02 | 0.03 | 0.03 | 0.20 |
| Session State Load | 0.09 | 0.09 | 0.15 | 0.20 | 0.53 |
| Security Policy Eval | 0.88 | 0.84 | 1.03 | 1.35 | 1.70 |
| Session State Save | 0.10 | 0.10 | 0.19 | 0.26 | 0.35 |
| Binary Startup/IO Overhead | 3.89 | 3.82 | 4.20 | 5.24 | 12.28 |
| Total Process Execution | 4.98 | 4.89 | 5.45 | 6.57 | 14.07 |
