# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Target URL**: `https://lilith-zero.badcompany.xyz/analyze-tool-execution`
- **Virtual Users (VUs)**: 10
- **Throughput Mode / Lock Contention**: Randomized Sessions (Independent Storage Writes)
- **Storage Tier under Test**: **Azure Files Share**
- **Total Requests Evaluated**: 3314
- **Throughput**: 33.06 req/s
- **Error Rate**: 0.00%
- **Status**: ✓ PASS

## Detailed Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) | P(99) (ms) |
|---|---|---|---|---|---|---|---|
| HTTP Request Duration | 287.94 | 125.46 | 256.86 | 1120.01 | 457.60 | 553.06 | 797.52 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | P(99) (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 5.92 | 1.53 | 18.30 | 41.56 | 131.03 |
| Session State Load | 0.02 | 0.01 | 0.02 | 0.04 | 17.38 |
| Security Policy Eval | 4.16 | 1.03 | 16.32 | 28.47 | 118.72 |
| Session State Save | 16.32 | 13.27 | 31.79 | 48.58 | 219.46 |
| Total Server Time | 28.86 | 24.59 | 60.18 | 88.91 | 223.04 |
