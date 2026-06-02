# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Total Requests**: 1809
- **Throughput**: 177.49 req/s
- **Error Rate**: 0.00%
- **Status**: ✓ PASS

## Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) |
|---|---|---|---|---|---|---|
| HTTP Request Duration | 44.24 | 5.54 | 40.62 | 203.60 | 68.95 | 85.45 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | Max (ms) |
|---|---|---|---|---|
| Session Lock Acquire | 13.87 | 12.48 | 24.64 | 126.58 |
| Session State Load | 2.13 | 1.92 | 3.82 | 9.82 |
| Security Policy Eval | 1.01 | 0.71 | 2.65 | 12.22 |
| Session State Save | 2.17 | 1.90 | 3.58 | 42.59 |
| Total Server Time | 21.39 | 19.11 | 36.99 | 136.05 |
