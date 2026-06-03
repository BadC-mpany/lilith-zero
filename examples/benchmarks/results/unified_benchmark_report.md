# Lilith-Zero: Deployment Benchmark & Verification Report


---

## 1. Multi-Deployment Performance & Latency Matrix

| Deployment Type | Storage / Files Tier | Active Policies | Payloads Tested | Concurrent Load (VUs) | Throughput (req/s) | Error Rate | Avg Latency (ms) | Med Latency (ms) | P95 Latency (ms) | P99 Latency (ms) |
|---|---|---|---|---|---|---|---|---|---|---|
| **Local App Hook (Claude)** | Local SSD | 1 Cedar | 1000 | N/A (Seq) | Sequential | 0.00% | 4.69 | 4.64 | 4.99 | 5.63 |
| **Local App Hook (Copilot)**| Local SSD | 1 Cedar | 1000 | N/A (Seq) | Sequential | 0.00% | 4.98 | 4.89 | 5.45 | 6.57 |
| **Webhook (Local, Static Session)** | Local SSD | 1 Cedar | 641762 | 100 | 6416.85 | 0.00% | 3.43 | 2.17 | 10.89 | 20.09 |
| **Webhook (Local, Random Sessions)**| Local SSD | 1 Cedar | 594570 | 100 | 5944.03 | 0.00% | 3.99 | 2.36 | 13.18 | 24.36 |
| **Webhook (Azure, Static Session)** | Azure Files Share | 1 Cedar | 2207 | 10 | 21.97 | 0.00% | 438.57 | 435.29 | 719.51 | 898.52 |
| **Webhook (Azure, Random Sessions)**| Azure Files Share | 1 Cedar | 3314 | 10 | 33.06 | 0.00% | 287.94 | 256.86 | 553.06 | 797.52 |

*Note: CLI Latencies measure complete cold-start process execution. Webhook latencies measure client round-trip HTTP request durations.*

---

## 2. Test Execution & Coverage Summary

### 2.1 Test Suite Scale
- **Differential Verification Scenarios**: 8 equivalent test cases (validating exact CLI vs Webhook decision output).
- **Fuzzing Robustness Scenarios**: 5/5 cases evaluating malformed/overflow inputs.
- **Lock Contention & Taint Persistence Scenarios**: 3 scenarios.
- **Policies Loaded**:
  - Cedar Policy Engine: 1 Policy Set (48 Cedar rules)
 
### 2.2 System Robustness & Fail-Closed Validation
- **Fail-Closed on Invalid Input**: **PASS** (rejections on malformed JSON, deep nesting, null bytes, and traversal paths).
- **File Descriptor Leak Delta**: **0 FDs** (monitored via `/proc` during active load).
- **Memory Footprint**:
  - CLI hook execution peak memory: **28464 KB**
  - Webhook daemon peak memory (VmHWM): **10496 KB**

---

## 3. Storage and File Access Load Analysis

### 3.1 Session Serialization and Lock Contention
Lilith-Zero serializes write actions per session (conversation) using file-system advisory locking. Under load tests:
- **Static Session (High Contention)**: Forces multiple concurrent virtual users (VUs) to block on the same lock. High lock wait times indicate correct execution sequencing to prevent state corruption.
- **Randomized Sessions (Independent Storage Writes)**: Bypasses lock contention by routing each VU to its own conversation ID, maximizing concurrent write operations on the underlying storage tier.

### 3.2 Azure Files Integration (Azure Webhook)
When deployed to Azure, Lilith-Zero utilizes Azure Files Share for cross-container session storage.
- Running load testing with randomized sessions against `https://lilith-zero.badcompany.xyz` stresses the Azure Files network attach layer.
- Throughput and P99 latency during Azure File writes indicate the latency profile introduced by network storage synchronization.
