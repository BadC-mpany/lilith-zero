# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Target URL**: `http://127.0.0.1:8080/analyze-tool-execution`
- **Virtual Users (VUs)**: 100
- **Throughput Mode / Lock Contention**: Randomized Sessions (Independent Storage Writes)
- **Storage Tier under Test**: **Local Disk Storage**
- **Total Requests Evaluated**: 594570
- **Throughput**: 5944.03 req/s
- **Error Rate**: 0.00%
- **Status**: ✓ PASS

## Detailed Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) | P(99) (ms) |
|---|---|---|---|---|---|---|---|
| HTTP Request Duration | 3.99 | 0.11 | 2.36 | 182.18 | 9.15 | 13.18 | 24.36 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | P(99) (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| Session State Load | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| Security Policy Eval | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| Session State Save | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| Total Server Time | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
