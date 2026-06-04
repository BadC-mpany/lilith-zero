# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Target URL**: `https://lilith-zero.badcompany.xyz/analyze-tool-execution`
- **Virtual Users (VUs)**: 250
- **Throughput Mode / Lock Contention**: Randomized Sessions (Independent Storage Writes)
- **Storage Tier under Test**: **Azure Ephemeral Disk (/tmp)**
- **Total Requests Evaluated**: 55185
- **Throughput**: 549.35 req/s
- **Error Rate**: 0.00%
- **Status**: ✓ PASS

## Detailed Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) | P(99) (ms) |
|---|---|---|---|---|---|---|---|
| HTTP Request Duration | 438.98 | 107.31 | 423.63 | 1249.94 | 650.04 | 710.00 | 886.77 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | P(99) (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 0.29 | 0.08 | 0.39 | 2.58 | 296.56 |
| Session State Load | 0.02 | 0.01 | 0.02 | 0.12 | 22.76 |
| Security Policy Eval | 1.45 | 0.80 | 4.83 | 10.04 | 66.74 |
| Session State Save | 0.10 | 0.03 | 0.09 | 0.88 | 273.13 |
| Total Server Time | 3.33 | 1.32 | 7.39 | 43.78 | 311.20 |
