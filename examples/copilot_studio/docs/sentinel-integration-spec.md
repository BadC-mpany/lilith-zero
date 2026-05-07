# Sentinel Integration Technical Specification

Lilith Zero → Microsoft Sentinel unified security data.

---

## Current lilith-telemetry Architecture

lilith-telemetry implements a Jaeger-like distributed tracing system:

```
lilith-zero process (FlockMember)
    │
    │  BinaryEvent (76-byte header + payload)
    │  encrypted ChaCha20-Poly1305, UDP, non-blocking
    ▼
FlockHead collector
    │
    ├── telemetry.log  (human-readable, timestamped)
    └── telemetry.json (structured JSON for dashboard)
```

**BinaryEvent wire format** (76 bytes fixed header):

| Field | Size | Description |
|---|---|---|
| `timestamp` | 8b | CPU RDTSC cycle counter |
| `session_id_hi/lo` | 16b | 128-bit session ID |
| `trace_id_hi/lo` | 16b | 128-bit OTel-compatible trace ID |
| `span_id` | 8b | 64-bit OTel-compatible span ID |
| `parent_span_id` | 8b | Parent span (0 = root) |
| `agent_id` | 8b | Node key ID from `flock_keys.db` |
| `thread_id` | 4b | Hardware thread ID |
| `policy_id` | 4b | Security policy rule ID (u32) |
| `kind` | 1b | OTel SpanKind (0=Internal … 4=Consumer) |
| `event_level` | 1b | 0=CriticalDeny, 1=RoutineAllow, 255=SessionInit |
| `payload_len` | 2b | Payload byte count |
| `payload` | var | Raw bytes (currently unstructured) |

The baggage system carries OTel-standard `TraceId` (128-bit), `SpanId` (64-bit), `SpanKind`, and `SessionId` through async boundaries — already structurally compatible with OpenTelemetry.

**TelemetryHook interface** (what lilith-zero calls into lilith-telemetry):

```rust
fn on_session_start(&self, session_id: &str)
fn begin_tool_evaluation(&self, session_id, tool_name) -> Box<dyn Any>
fn on_tool_decision(&self, session_id, tool_name, allowed: bool, reason: Option<&str>)
fn on_policy_error(&self, session_id, tool_name, error)
fn begin_mcp_request(&self, method, params) -> Box<dyn Any>
fn on_forward_upstream(&self, method)
fn begin_mcp_response(&self) -> Box<dyn Any>
fn on_forward_client(&self)
```

---

## Gaps: What lilith-telemetry Currently Does NOT Capture (It's not necessary to add them all. this should be discussed)

| Missing data | Impact on Sentinel |
|---|---|
| **Taint set at decision time** | Cannot detect lethal trifecta patterns in KQL |
| **Copilot Studio `conversationId` / `agent_id`** | Cannot join Lilith rows to Copilot Studio events |
| **Tool arguments summary** | No forensic context on what was blocked |
| **Cedar rule ID** (separate from reason text) (also we should include the actual policy file somehow) | Cannot filter/group by policy rule in KQL |
| **Wall-clock timestamp** | RDTSC is not usable in Sentinel; no `TimeGenerated` |
| **`policy_id` u32 field** | Always 0 — never populated from the evaluation path |
| **Structured payload** | Raw bytes in BinaryEvent; FlockHead writes untyped strings |

---

## Recommended Architecture: OTLP → Azure Monitor

The cleanest integration path — the one that "seamlessly integrates with everyone else" — is **OpenTelemetry Protocol (OTLP)**.

```
lilith-zero (FlockMember)
    │ OTLP/gRPC or HTTP
    ▼
OTel Collector (sidecar)
    │
    ├──► Azure Monitor Logs Ingestion → Log Analytics → Sentinel
    ├──► Datadog / Grafana / Splunk (same collector, different exporter)
    └──► stdout / debug
```

lilith-telemetry's baggage already has 128-bit TraceID, 64-bit SpanID, and SpanKind — the three fields OTel requires for a span. Adding an OTLP exporter is a drop-in replacement for the current UDP+encryption path.

**Why not a custom Log Ingestion API call directly?**
A direct REST POST from FlockHead to Sentinel works but creates a point-to-point coupling. OTLP exporter from a collector is vendor-neutral: swap the exporter config, not the code.

---

## Target Sentinel Table: ASimAuditEventLogs

Sentinel's ASIM (Advanced Security Information Model) `ASimAuditEventLogs` is the correct normalized table for security policy enforcement decisions. It maps cleanly to Lilith's event semantics:

| ASIM field | Class | Lilith source | Value example |
|---|---|---|---|
| `TimeGenerated` | Mandatory | wall-clock at event | `2026-05-07T14:23:01Z` |
| `EventType` | Mandatory | constant | `"Execute"` |
| `EventResult` | Mandatory | `allowed` bool | `"Success"` / `"Failure"` |
| `EventResultDetails` | Recommended | `reason` text | `"Blocked: Python code contains prohibited patterns"` |
| `EventSeverity` | Recommended | `event_level` | `"High"` (CriticalDeny) / `"Informational"` (RoutineAllow) |
| `EventProduct` | Mandatory | constant | `"Lilith Zero"` |
| `EventVendor` | Mandatory | constant | `"BadCompany"` |
| `EventSchema` | Mandatory | constant | `"AuditEvent"` |
| `EventSchemaVersion` | Mandatory | constant | `"0.1.2"` |
| `Operation` | Mandatory | tool name | `"Send-an-Email"` |
| `Object` | Mandatory | Cedar rule ID | `"guardrail:code_injection"` |
| `ObjectType` | Conditional | constant | `"Policy Rule"` |
| `RuleName` | Optional | Cedar rule ID | `"lethal_trifecta:email_untrusted_recipient"` |
| `ActorSessionId` | Optional | Lilith session_id | `"abc123..."` |
| `TargetAppId` | Optional | Copilot Studio agent_id | `"5be3e14e-..."` |
| `TargetAppName` | Optional | constant | `"Copilot Studio"` |
| `DvcAction` | Recommended | allow/deny | `"Allow"` / `"Deny"` |
| `AdditionalFields` | Optional | taint_set, trace_id | `{"taints":"ACCESS_PRIVATE,UNTRUSTED_SOURCE","trace_id":"..."}` |

The `ASimAuditEventLogs` table is **directly supported** by the Log Ingestion API, meaning Lilith events can be sent to it without a `_CL` custom table — they will participate in `imAuditEvent` unified queries automatically.

---

## Azure Infrastructure Requirements

### Azure-side setup (one-time, per customer environment)

1. **App Registration** (Microsoft Entra ID)
   - Create a service principal for Lilith to authenticate
   - Generate a client secret or certificate
   - Required: `Application (client) ID`, `Directory (tenant) ID`, secret `Value`

2. **Log Analytics Workspace** (or use existing Sentinel workspace)
   - The `ASimAuditEventLogs` table is built-in — no table creation needed
   - Note: `ASimAuditEventLogs` uses Analytics tier (billed per GB ingested)

3. **Data Collection Rule (DCR)** — kind: `"Direct"`
   - Declares the stream schema matching the JSON Lilith sends
   - `transformKql`: maps Lilith JSON fields to ASIM field names
   - `outputStream`: `"Microsoft-ASimAuditEventLogs"`
   - Grant the App Registration the **Monitoring Metrics Publisher** role on the DCR

4. **DCR Ingestion Endpoint**
   - Retrieved from DCR overview in Azure portal (JSON view)
   - Format: `https://{dcr-logs-endpoint}.ingest.monitor.azure.com/dataCollectionRules/{dcr-immutable-id}/streams/Microsoft-ASimAuditEventLogs?api-version=2023-01-01`
   - TLS 1.2+ required (enforced from March 2026)

5. **(Optional) Data Collection Endpoint (DCE)** — only needed for private link

### OTel Collector setup

```yaml
# otelcol-config.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  azuremonitorlogs:
    dcr_immutable_id: "dcr-00a00a..."
    endpoint: "https://...ingest.monitor.azure.com"
    stream_name: "Microsoft-ASimAuditEventLogs"
    tenant_id: "${AZURE_TENANT_ID}"
    client_id: "${AZURE_CLIENT_ID}"
    client_secret: "${AZURE_CLIENT_SECRET}"

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [azuremonitorlogs]
```

---

## Required Changes to lilith-telemetry and lilith-zero

### 1. Enrich TelemetryHook.on_tool_decision

Add the missing fields so the hook implementation has all data needed for a complete Sentinel record:

```rust
fn on_tool_decision(
    &self,
    session_id: &str,
    tool_name: &str,
    allowed: bool,
    reason: Option<&str>,
    // New fields needed:
    taint_set: &[String],              // taints active at decision time
    rule_id: Option<&str>,             // Cedar rule @id annotation
    external_session_id: Option<&str>, // Copilot Studio conversationId (if set)
)
```

### 2. Structured JSON payload in BinaryEvent

Replace raw-bytes payload with a JSON object so the FlockHead can forward structured records:

```json
{
  "event_type": "tool_decision",
  "tool_name": "Send-an-Email",
  "allowed": false,
  "reason": "Blocked: sending to untrusted recipient...",
  "rule_id": "lethal_trifecta:email_untrusted_recipient",
  "taint_set": ["ACCESS_PRIVATE", "UNTRUSTED_SOURCE"],
  "external_session_id": "df3f67b1-bc86-4dc8-9b79-05fa0cbb9e4b",
  "wall_clock_utc": "2026-05-07T14:23:01.234Z"
}
```

### 3. FlockHead OTLP emitter

Add to `FlockHead`: after decrypting and parsing each BinaryEvent, emit it as an OTel log record via the OTLP gRPC or HTTP exporter. The OTel Collector handles the rest.

Alternatively, the FlockHead can POST directly to the Log Ingestion API endpoint — simpler but couples to Azure.

### 4. Set policy_id in BinaryEvent

In `security_core.rs`, after Cedar evaluation, populate `baggage.security_policy_id` with a hash of the fired Cedar rule ID so the field carries useful data.

---

## Data Completeness Assessment

| Data item | Currently logged? | After changes? |
|---|---|---|
| Session ID | Yes (Lilith internal) | Yes |
| Tool name | Yes | Yes |
| ALLOW/DENY decision | Yes | Yes |
| Denial reason text | Yes (via HMAC audit log) | Yes (structured) |
| Cedar rule ID | No — embedded in reason text | Yes (dedicated field) |
| Taint set at decision | No | Yes |
| Copilot Studio conversationId | No | Yes |
| Copilot Studio agent ID | No | Yes |
| Tool arguments | No | Partial (summary, PII-scrubbed) |
| Wall-clock timestamp | No (RDTSC only) | Yes (wall_clock_utc in payload) |
| HMAC-signed audit proof | Yes (separate audit.jsonl) | Yes (unchanged) |
| OTel TraceID / SpanID | Yes (baggage) | Yes (OTLP native) |
| Session init event | Yes | Yes |
| Gap markers (dropped records) | Yes | Yes |

The existing HMAC-signed JSONL audit log (`audit.jsonl`) is complementary and unchanged — it remains the forensic proof chain. The Sentinel integration is a forward pipeline for operational correlation, not a replacement.

---

## Log Retention and Volume Estimate

| Tier | Retention | Cost model | Suitable for |
|---|---|---|---|
| Analytics | 90 days (default, configurable to 2 years) | Per GB ingested + per GB retained | Active KQL queries, alerts, Sentinel rules |
| Basic Logs | 8 days | Lower ingestion cost, no KQL alerting | High-volume RoutineAllow events |
| Auxiliary | 30 days | Lowest cost | Archive / compliance |

Recommendation: route `CriticalDeny` events to Analytics tier, `RoutineAllow` to Basic Logs. Apply a DCR `transformKql` filter to split on `event_level`.

---

## Sources

- [Azure Monitor Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)
- [ASIM Audit Event normalization schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-audit)
- [ASimAuditEventLogs supported table for Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview#supported-tables)
- [OTel Protocol ingestion into Azure Monitor (preview)](https://learn.microsoft.com/en-us/azure/azure-monitor/containers/opentelemetry-protocol-ingestion)
- [HTTP Data Collector API deprecation (Sept 2026)](https://techcommunity.microsoft.com/blog/microsoft-security-blog/action-required-transition-from-http-data-collector-api-in-microsoft-sentinel/4499777)
- [Microsoft Copilot Data Connector for Sentinel (public preview)](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/the-microsoft-copilot-data-connector-for-microsoft-sentinel-is-now-in-public-pre/4491986)
- [Custom data ingestion in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/data-transformation)
