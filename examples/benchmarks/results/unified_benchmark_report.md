# Lilith-Zero: Multi-Deployment Benchmark & Verification Report

Lilith-Zero is a deterministic, formally-verified, sub-millisecond security middleware for AI agents using the Model Context Protocol (MCP). It runs as a process supervisor (CLI App Hook) or webhook evaluator, enforcing deny-by-default policies with type-safe taint tracking.

This report is compiled programmatically by aggregating execution data from individual test runners.

---

## 1. Multi-Deployment Performance & Latency Matrix

| Deployment Type | Storage / Files Tier | Active Policies | Payloads Tested | Concurrent Load (VUs) | Throughput (req/s) | Error Rate | Avg Latency (ms) | Med Latency (ms) | P95 Latency (ms) | P99 Latency (ms) |
|---|---|---|---|---|---|---|---|---|---|---|
| **Local App Hook (Claude)** | Local SSD | 1 YAML | *Pending* | N/A (Seq) | Sequential | 0.00% | *Pending* | *Pending* | *Pending* | *Pending* |
| **Local App Hook (Copilot)**| Local SSD | 1 YAML | *Pending* | N/A (Seq) | Sequential | 0.00% | *Pending* | *Pending* | *Pending* | *Pending* |
| **Webhook Server (Local)** | Local SSD | 1 YAML | 48409 | 10 | 6761.76 | 100.00% | 0.00 | 0.00 | 0.00 | 0.00 |
| **Webhook Server (Azure)** | Azure Files Share | 1 YAML | *Pending* | *Pending* | *Pending* | *Pending* | *Pending* | *Pending* | *Pending* | *Pending* |

*Note: CLI Latencies measure complete cold-start process execution. Webhook latencies measure client round-trip HTTP request durations.*

---

## 2. Test Execution & Coverage Summary

### 2.1 Test Suite Scale
- **Differential Verification Scenarios**: 8 equivalent test cases (validating exact CLI vs Webhook decision output).
- **Fuzzing Robustness Scenarios**: 5/5 cases evaluating malformed/overflow inputs.
- **Lock Contention & Taint Persistence Scenarios**: 0 scenarios.
- **Policies Loaded**:
  - Legacy YAML Engine: 1 Policy File (Benchmark Policy)
  - Cedar Policy Engine: 1 Policy Set (48 Cedar rules)

### 2.2 System Robustness & Fail-Closed Validation
- **Fail-Closed on Invalid Input**: **PASS** (rejections on malformed JSON, deep nesting, null bytes, and traversal paths).
- **File Descriptor Leak Delta**: **0 FDs** (monitored via `/proc` during active load).
- **Memory Footprint**:
  - CLI hook execution peak memory: **0 KB**
  - Webhook daemon peak memory (VmHWM): **0 KB**

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
