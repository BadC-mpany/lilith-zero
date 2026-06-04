# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Target URL**: `https://lilith-zero.badcompany.xyz/analyze-tool-execution`
- **Virtual Users (VUs)**: 100
- **Throughput Mode / Lock Contention**: Static Session (High Lock Contention)
- **Storage Tier under Test**: **Azure Files Share**
- **Total Requests Evaluated**: 3415
- **Throughput**: 33.22 req/s
- **Error Rate**: 0.00%
- **Status**: ✓ PASS

## Detailed Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) | P(99) (ms) |
|---|---|---|---|---|---|---|---|
| HTTP Request Duration | 2945.08 | 216.20 | 2914.13 | 7550.17 | 3256.44 | 3980.04 | 5826.73 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | P(99) (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 2.10 | 1.17 | 7.90 | 17.12 | 46.22 |
| Session State Load | 0.05 | 0.03 | 0.03 | 0.08 | 8.18 |
| Security Policy Eval | 3.21 | 0.62 | 10.13 | 20.32 | 233.31 |
| Session State Save | 35.76 | 33.30 | 52.23 | 67.99 | 91.93 |
| Total Server Time | 43.30 | 40.00 | 67.68 | 89.81 | 344.63 |
