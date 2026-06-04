# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Target URL**: `http://127.0.0.1:8080/analyze-tool-execution`
- **Virtual Users (VUs)**: 100
- **Throughput Mode / Lock Contention**: Static Session (High Lock Contention)
- **Storage Tier under Test**: **Local Disk Storage**
- **Total Requests Evaluated**: 3673
- **Throughput**: 35.73 req/s
- **Error Rate**: 0.00%
- **Status**: ✓ PASS

## Detailed Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) | P(99) (ms) |
|---|---|---|---|---|---|---|---|
| HTTP Request Duration | 2749.13 | 36.75 | 2482.77 | 6857.95 | 4393.33 | 4806.81 | 5645.89 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | P(99) (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 77.84 | 75.42 | 89.32 | 148.75 | 193.24 |
| Session State Load | 14.00 | 13.60 | 16.52 | 23.95 | 53.26 |
| Security Policy Eval | 0.48 | 0.45 | 0.66 | 0.86 | 6.55 |
| Session State Save | 13.43 | 12.85 | 15.98 | 25.95 | 87.24 |
| Total Server Time | 109.73 | 106.31 | 127.75 | 203.76 | 252.46 |
