# Lilith-Zero Telemetry & Observability Architecture

This document describes the OpenTelemetry (OTel) architecture for the Lilith-Zero security middleware. The design ensures comprehensive observability—from real-time operational metrics to deep forensic auditing—while maintaining minimal latency and supporting both centralized and edge deployment models.

---

## 1. Observability Strategy (Dual-Signal Approach)

To prevent dashboard noise and storage bloat while capturing "everything," telemetry is split into two tiers natively supported by the Rust `tracing` ecosystem.

### Tier 1: Spans & Attributes (Real-Time Monitoring)
**Purpose:** Fast, highly-indexed metadata useful while the agent is running.
- **Data Captured:** Latency (automatic), tool name, policy decision (`ALLOW`/`DENY`), triggered rule/reason, session ID, and active taints.
- **Usage:** Dashboards for real-time latency monitoring, throughput, and instant alert triggering on security blocks.

### Tier 2: Span Events (Comprehensive Audit Logging)
**Purpose:** High-volume forensic data that logs absolutely everything.
- **Data Captured:** Raw JSON payloads (tool inputs/outputs), cryptographic hashes of data flows (for mathematical traceability without reading the payload), raw evaluated policies, and extensive context dumps.
- **Usage:** Deep forensic investigation. These events are attached to the Spans but are queried differently (e.g., in ClickHouse or Elasticsearch).

---

## 2. Deployment Scenarios

Lilith exports data using the OpenTelemetry Protocol (OTLP). The architecture seamlessly transitions between deployment models using configuration variables, with zero code changes required.

### Scenario A: Central API Deployment
*The Agent and Lilith-Zero run on a central corporate server. Users interact with the agent via an API.*

- **Execution:** Lilith intercepts agent tool calls on the server.
- **Telemetry Flow:** The Rust OTLP exporter sends batches of telemetry over gRPC/HTTP directly to a local, on-premise OpenTelemetry Collector (`localhost:4317`).
- **Security:** Since traffic is internal (loopback or VPC), standard unencrypted HTTP/gRPC is sufficient and maximizes throughput.

### Scenario B: Local / Edge Deployment
*The Agent and Lilith-Zero run natively on employees' local machines, intercepting local file system and OS tool access.*

- **Execution:** Lilith intercepts the local agent's actions on the employee's computer.
- **Telemetry Flow:** The Rust OTLP exporter batches telemetry and streams it over the internet/intranet to a central corporate OpenTelemetry Collector (e.g., `https://telemetry.badcompany.internal:4317`).
- **Security:** 
    - **Encryption:** The exporter connects via TLS.
    - **Authentication:** API keys or mTLS certificates are attached to the OTLP headers to verify the identity of the employee's machine.
    - **Resilience:** The exporter buffers data locally if the employee loses internet connection, ensuring no logs are lost.

---

## 3. Codebase Organization

To keep the codebase clean and maintainable, all telemetry configuration is isolated to a single file, while the rest of the application simply calls semantic logging nodes.

### The Central Telemetry Manager
**File:** `lilith-zero/src/telemetry.rs`
- **Responsibility:** This is the *only* file that imports OpenTelemetry SDK dependencies. It sets up the OTLP exporter, configures the async batch processor (Tokio), handles environment variables (Endpoint URL, API tokens), and initializes the global `tracing_subscriber` registry.
- **Why:** Keeps the core engine pure. If the telemetry backend changes, only this one file is updated.

### The Instrumentation Nodes
**Files:** `lilith-zero/src/mcp/server.rs`, `lilith-zero/src/engine_core/policy.rs`, etc.
- **Responsibility:** These files contain the actual business logic and are decorated with lightweight `tracing` macros (`#[instrument]`, `tracing::info!`, `tracing::Span::record`).
- **Example Usage:**

```rust
// Example Node: Intercepting a tool call in mcp/server.rs

use tracing::{instrument, Span, info, error};

#[instrument(
    name = "lilith.mcp.tool_call",
    skip_all,
    fields(
        session_id = %session.id,
        tool_name = %request.tool,
        decision = tracing::field::Empty,
        latency_ms = tracing::field::Empty
    )
)]
pub async fn handle_tool_call(request: ToolRequest) -> Result<ToolResponse> {
    // 1. Log the heavy audit data as an Event inside the Span
    let payload_hash = hash_payload(&request.args);
    info!(
        event.type = "audit.ingress",
        payload.raw = ?request.args,
        payload.hash = %payload_hash,
        "Received upstream tool request"
    );

    // 2. Perform security evaluation
    let result = evaluate_policy(&request).await;

    // 3. Record the real-time operational decision onto the Span
    match result {
        Ok(res) => {
            Span::current().record("decision", &"ALLOW");
            info!(event.type = "audit.egress", payload.raw = ?res, "Execution allowed");
            Ok(res)
        },
        Err(e) => {
            Span::current().record("decision", &"DENY");
            error!(event.type = "audit.block", reason = %e, "Execution blocked by policy");
            Err(e)
        }
    }
}
```

---

## 4. Analytics and Dashboarding

By streaming this structured data to a central OpenTelemetry Collector, you can route the dual-signals appropriately:
1. **Traces/Spans** route to Tempo/Jaeger for latency heatmaps and success rates.
2. **Events** route to ClickHouse/Elasticsearch for heavy text searching, hash matching, and forensic audits.
3. **Grafana** sits on top, providing a single unified dashboard connecting the speed of traces with the depth of the logs.
