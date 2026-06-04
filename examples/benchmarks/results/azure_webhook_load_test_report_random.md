# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Target URL**: `https://lilith-zero.badcompany.xyz/analyze-tool-execution`
- **Virtual Users (VUs)**: 100
- **Throughput Mode / Lock Contention**: Randomized Sessions (Independent Storage Writes)
- **Storage Tier under Test**: **Azure Files Share**
- **Total Requests Evaluated**: 4383
- **Throughput**: 42.59 req/s
- **Error Rate**: 0.00%
- **Status**: ✓ PASS

## Detailed Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) | P(99) (ms) |
|---|---|---|---|---|---|---|---|
| HTTP Request Duration | 2290.01 | 132.63 | 2145.03 | 5481.18 | 3087.02 | 3447.83 | 4094.83 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | P(99) (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 6.93 | 2.15 | 19.35 | 67.87 | 151.84 |
| Session State Load | 0.05 | 0.01 | 0.03 | 0.06 | 18.80 |
| Security Policy Eval | 5.49 | 1.40 | 18.60 | 37.03 | 106.96 |
| Session State Save | 17.05 | 13.24 | 32.87 | 50.33 | 110.84 |
| Total Server Time | 32.90 | 28.89 | 68.18 | 109.79 | 203.47 |
