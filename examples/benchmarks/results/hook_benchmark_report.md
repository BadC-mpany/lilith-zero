# Lilith Zero: CLI Hook Latency Benchmark Report

## Execution Summary
- **Total Invocations**: 100
- **Correct Decisions**: 100
- **Mismatches**: 0
- **Policy Enforcement Accuracy**: 100.00%
- **Total Benchmark Duration**: 0.543s
- **Status**: ✓ PASS

## Latency Metrics Breakdown (ms)

| Metric Phase            | Avg (ms) | Med (ms) | P95 (ms) | P99 (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 0.02 | 0.02 | 0.03 | 0.04 | 0.05 |
| Session State Load | 0.03 | 0.03 | 0.04 | 0.05 | 0.05 |
| Security Policy Eval | 0.95 | 0.91 | 1.22 | 1.28 | 1.30 |
| Session State Save | 0.04 | 0.04 | 0.06 | 0.09 | 0.18 |
| Binary Startup/IO Overhead | 4.34 | 4.25 | 4.96 | 5.32 | 5.75 |
| Total Process Execution | 5.37 | 5.26 | 6.09 | 6.33 | 6.88 |
