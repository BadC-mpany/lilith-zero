# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Target URL**: `http://127.0.0.1:8080/analyze-tool-execution`
- **Virtual Users (VUs)**: 100
- **Throughput Mode / Lock Contention**: Static Session (High Lock Contention)
- **Storage Tier under Test**: **Local Disk Storage**
- **Total Requests Evaluated**: 7097
- **Throughput**: 69.94 req/s
- **Error Rate**: 0.00%
- **Status**: ✓ PASS

## Detailed Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) | P(99) (ms) |
|---|---|---|---|---|---|---|---|
| HTTP Request Duration | 1408.24 | 26.01 | 1297.55 | 3328.48 | 1885.83 | 2014.73 | 2826.77 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | P(99) (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 39.53 | 38.99 | 43.58 | 53.71 | 228.60 |
| Session State Load | 7.11 | 6.96 | 8.25 | 10.16 | 32.50 |
| Security Policy Eval | 0.48 | 0.45 | 0.63 | 0.79 | 2.51 |
| Session State Save | 6.68 | 6.44 | 8.07 | 10.31 | 174.76 |
| Total Server Time | 56.00 | 55.33 | 61.04 | 75.94 | 245.71 |
