# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Target URL**: `http://127.0.0.1:8080/analyze-tool-execution`
- **Virtual Users (VUs)**: 1000
- **Throughput Mode / Lock Contention**: Randomized Sessions (Independent Storage Writes)
- **Storage Tier under Test**: **Local Disk Storage**
- **Total Requests Evaluated**: 177611
- **Throughput**: 1767.74 req/s
- **Error Rate**: 0.00%
- **Status**: ✓ PASS

## Detailed Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) | P(99) (ms) |
|---|---|---|---|---|---|---|---|
| HTTP Request Duration | 552.05 | 37.41 | 533.69 | 1173.79 | 747.76 | 816.49 | 937.12 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | P(99) (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 0.14 | 0.09 | 0.34 | 1.31 | 13.56 |
| Session State Load | 0.02 | 0.01 | 0.02 | 0.09 | 14.03 |
| Security Policy Eval | 1.44 | 0.91 | 3.78 | 6.97 | 46.22 |
| Session State Save | 0.06 | 0.04 | 0.10 | 0.76 | 54.03 |
| Total Server Time | 2.08 | 1.56 | 5.09 | 8.55 | 54.86 |
