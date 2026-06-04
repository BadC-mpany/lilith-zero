# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Target URL**: `http://127.0.0.1:8080/analyze-tool-execution`
- **Virtual Users (VUs)**: 100
- **Throughput Mode / Lock Contention**: Randomized Sessions (Independent Storage Writes)
- **Storage Tier under Test**: **Local Disk Storage**
- **Total Requests Evaluated**: 185233
- **Throughput**: 1851.54 req/s
- **Error Rate**: 0.00%
- **Status**: ✓ PASS

## Detailed Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) | P(99) (ms) |
|---|---|---|---|---|---|---|---|
| HTTP Request Duration | 42.51 | 1.09 | 40.81 | 189.09 | 68.45 | 77.45 | 96.84 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | P(99) (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 0.13 | 0.08 | 0.27 | 1.26 | 14.09 |
| Session State Load | 0.02 | 0.01 | 0.02 | 0.08 | 7.36 |
| Security Policy Eval | 1.39 | 0.88 | 3.61 | 5.88 | 46.62 |
| Session State Save | 0.06 | 0.03 | 0.09 | 0.82 | 13.06 |
| Total Server Time | 1.98 | 1.50 | 4.66 | 7.22 | 47.35 |
