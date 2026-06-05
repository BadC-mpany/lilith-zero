# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Target URL**: `https://lilith-zero.badcompany.xyz/analyze-tool-execution`
- **Virtual Users (VUs)**: 50
- **Throughput Mode / Lock Contention**: Static Session (High Lock Contention)
- **Storage Tier under Test**: **Azure Ephemeral Disk (/tmp)**
- **Total Requests Evaluated**: 8998
- **Throughput**: 298.06 req/s
- **Error Rate**: 0.00%
- **Status**: ✓ PASS

## Detailed Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) | P(99) (ms) |
|---|---|---|---|---|---|---|---|
| HTTP Request Duration | 147.59 | 106.72 | 132.97 | 468.77 | 196.53 | 234.93 | 346.37 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | P(99) (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 1.29 | 0.91 | 4.34 | 7.74 | 21.34 |
| Session State Load | 0.69 | 0.60 | 1.58 | 2.59 | 14.27 |
| Security Policy Eval | 0.95 | 0.75 | 2.32 | 4.09 | 10.54 |
| Session State Save | 0.84 | 0.77 | 1.70 | 3.15 | 18.08 |
| Total Server Time | 4.91 | 4.61 | 10.48 | 15.49 | 26.90 |
