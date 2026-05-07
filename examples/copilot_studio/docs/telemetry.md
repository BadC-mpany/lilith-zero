# Copilot Studio + Lilith Zero: Telemetry & Observability

Factual findings on what data is captured where, what fields reach which surfaces, and what value Lilith's own audit log adds.

---

## The `reason` field in the webhook response

Lilith returns `reason` (populated from the Cedar `@reason` annotation of the matching forbid rule) in the `AnalyzeToolExecutionResponse`:

```json
{
  "blockAction": true,
  "reasonCode": 1002,
  "reason": "Blocked: Python code contains prohibited patterns (socket / shell execution)"
}
```

**Where this appears:**

| Surface | Shows `reason` text? | Notes |
|---|---|---|
| End-user chat message | No | Hardcoded: "This message was blocked by threat detection tools configured by your admin." |
| Agent's context/LLM | No | Execution halted; reason not fed back into the agent |
| Security Analytics (Copilot Studio) | No | Shows category-level counts (potential threats / auth / policies), not our text |
| Purview Audit Log | No | `CopilotInteraction` events log metadata only; webhook response fields not in schema |
| Dataverse ConversationTranscript | No | Captures bot framework activity types; no webhook response fields |
| **Lilith audit log (stderr/file)** | **Yes** | The only place the specific Cedar rule reason is recorded |
| Defender XDR portal | N/A | Only when using Microsoft Defender as the provider, not Lilith |

---

## "Rationale" in the Copilot Studio test UI

The "Rationale" label visible in the Copilot Studio test panel when a tool is blocked is **not** derived from our webhook response. It is the agent's own `plannerContext.thought` field — the LLM orchestrator's reasoning for why it selected that tool — which Copilot Studio sends *to us* in the inbound request. We cannot set, override, or influence it.

---

## Copilot Studio Security Analytics

Available at: Agent → Protection Status column → See details → Security analytics.

Shows, for last 7/14/30 days:
- **Reason for block** stacked bar chart: categories are "potential threats", "authentication", "policies", "content moderation" — not Lilith's specific rule reasons
- **Session block rate trend**: trend lines per category over time

None of this surfaces our `reason`, `reasonCode`, or `diagnostics` fields. The chart treats all Lilith blocks as one category ("potential threats" or "policies" depending on how the environment is configured).

---

## Lilith's audit log vs. everything else

Lilith's HMAC-signed JSONL audit log (emitted to stderr / optional file) is the **only** data source that records:

- The exact Cedar rule that fired (via `@reason` annotation)
- The session taint state at the time of the decision (`ACCESS_PRIVATE`, `UNTRUSTED_SOURCE`, etc.)
- A per-decision ALLOW/DENY audit trail with `conversationId` (= Copilot Studio `conversationId`)
- A cryptographic proof the log entry was not tampered with

Copilot Studio tells you *how many* things were blocked. Lilith tells you *which rule blocked what, and why, for each call*.

---

## Sentinel integration

No native connector exists for Lilith's audit data → Sentinel. To get Lilith decisions into Sentinel:

1. Stream Lilith's JSONL audit log to Azure Monitor via the Azure Monitor Agent or a custom Log Analytics ingestion endpoint
2. Define a custom Sentinel table (e.g., `LilithDecisions_CL`)
3. Write KQL detection rules on `Cedar_rule`, `taint_state`, `session_id`

Alternatively, if you switch to Microsoft Defender as the threat detection provider, it creates XDR alerts natively visible in the Defender portal and flowing into Sentinel without custom work — but you lose Cedar rule-level attribution and taint tracking.

---

## Sources

- [Build a runtime threat detection system for Copilot Studio agents](https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers) — full `AnalyzeToolExecutionResponse` schema
- [Enable external threat detection for Copilot Studio agents](https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider) — setup, generative-only restriction
- [Agent runtime protection status](https://learn.microsoft.com/en-us/microsoft-copilot-studio/security-agent-runtime-view) — Protection Status column, Security Analytics detail
- [Security and governance in Copilot Studio](https://learn.microsoft.com/en-us/microsoft-copilot-studio/security-and-governance) — full control list
- [View audit logs for Copilot Studio](https://learn.microsoft.com/en-us/microsoft-copilot-studio/admin-logging-copilot-studio) — Purview audit schema, Sentinel mention
- [Protect agents in real-time with Microsoft Defender](https://learn.microsoft.com/en-us/defender-cloud-apps/real-time-agent-protection-during-runtime) — Defender XDR alerts
- [Microsoft Copilot Data Connector for Sentinel (public preview)](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/the-microsoft-copilot-data-connector-for-microsoft-sentinel-is-now-in-public-pre/4491986) — `CopilotActivity` table, Feb 2026
- [Conversation transcripts in Power Apps](https://learn.microsoft.com/en-us/microsoft-copilot-studio/analytics-transcripts-powerapps) — Dataverse schema, no webhook fields
