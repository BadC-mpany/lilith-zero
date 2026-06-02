# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Target URL**: `http://localhost:8080/analyze-tool-execution`
- **Virtual Users (VUs)**: 10
- **Throughput Mode / Lock Contention**: Static Session (High Lock Contention)
- **Storage Tier under Test**: **Local Disk Storage**
- **Total Requests Evaluated**: 48409
- **Throughput**: 6761.76 req/s
- **Error Rate**: 100.00%
- **Status**: ✗ FAIL

## Detailed Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) | P(99) (ms) |
|---|---|---|---|---|---|---|---|
| HTTP Request Duration | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | P(99) (ms) | Max (ms) |
|---|---|---|---|---|---|
| Session Lock Acquire | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| Session State Load | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| Security Policy Eval | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| Session State Save | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| Total Server Time | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
