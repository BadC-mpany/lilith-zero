# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Target URL**: `https://lilith-zero.badcompany.xyz/analyze-tool-execution`
- **Virtual Users (VUs)**: 10
- **Throughput Mode / Lock Contention**: Static Session (High Lock Contention)
- **Storage Tier under Test**: **Azure Files Share**
- **Total Requests Evaluated**: 2207
- **Throughput**: 21.97 req/s
- **Error Rate**: 0.00%
- **Status**: ✓ PASS

## Detailed Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) | P(99) (ms) |
|---|---|---|---|---|---|---|---|
| HTTP Request Duration | 438.57 | 142.34 | 435.29 | 1134.03 | 647.58 | 719.51 | 898.52 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | P(99) (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 2.11 | 1.10 | 8.85 | 17.47 | 57.50 |
| Session State Load | 0.04 | 0.03 | 0.03 | 0.09 | 6.03 |
| Security Policy Eval | 2.56 | 0.60 | 9.74 | 19.57 | 99.66 |
| Session State Save | 37.45 | 34.44 | 59.61 | 76.64 | 118.45 |
| Total Server Time | 44.49 | 40.55 | 72.23 | 98.45 | 189.29 |
