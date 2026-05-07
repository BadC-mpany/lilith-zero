# Copilot Studio Threat Detection API Payload Schema

This document details the factual, real-world JSON payload format sent by the Microsoft Copilot Studio Threat Detection API to external webhook endpoints like Lilith Zero. This schema is critical for taint tracking and policy evaluation as it defines exactly where `conversationId`, `agent.id`, and tool execution arguments are located.

## 1. Raw Payload Example

This example was intercepted directly from a Copilot Studio session attempting to execute an "Excel Online (Business) - Create table" action.

```json
{
  "plannerContext": {
    "userMessage": "execute the tool again",
    "thought": "This action needs to be done to create a new table in the specified Excel Online workbook as requested by the user.",
    "chatHistory": [
      {
        "id": "63835de3-91ca-4735-80e7-40d5f964f4de",
        "role": "user",
        "content": "execute the tool again",
        "timestamp": "2026-05-02T14:34:58.1758533+00:00"
      },
      {
        "id": "405405f7-36f1-45d9-8299-a269951ca9a4",
        "role": "assistant",
        "content": "Error Message: The connector 'Excel Online (Business)' returned an HTTP error...",
        "timestamp": "2026-05-02T14:00:28.8665764+00:00"
      }
    ],
    "previousToolsOutputs": []
  },
  "toolDefinition": {
    "id": "cra65_otpdemo.action.ExcelOnlineBusiness-Createtable",
    "type": "ToolDefinition",
    "name": "Create-table",
    "description": "Create a new table in the Excel workbook.",
    "inputParameters": [
      {
        "name": "Location",
        "description": "Select from the drop-down or specify...",
        "type": { "$kind": "String" }
      }
    ],
    "outputParameters": []
  },
  "inputValues": {
    "source": "locationG",
    "Range": "table_rangeG",
    "file": "fileG",
    "drive": "doc_libG"
  },
  "conversationMetadata": {
    "agent": {
      "id": "5be3e14e-2e46-f111-bec6-7c1e52344333",
      "tenantId": "98e2f7d2-c1d3-4410-b87f-2396f157975f",
      "environmentId": "Default-98e2f7d2-c1d3-4410-b87f-2396f157975f",
      "name": "otp_demo",
      "version": null,
      "isPublished": false
    },
    "user": {
      "id": "4c9f97d9-375a-4fe2-8ae5-6c4fb08043ff",
      "tenantId": "98e2f7d2-c1d3-4410-b87f-2396f157975f"
    },
    "conversationId": "6dea8192-77ab-4305-8e75-c5c3472f43ce",
    "messageId": null,
    "channelId": "pva-studio",
    "planId": "6fbb84c7-b50b-4090-8a97-134afbd16c51",
    "planStepId": "4391ec44-bcf5-4d2d-81cf-f3ee84545f9f",
    "parentAgentComponentId": null,
    "trigger": {
      "id": null,
      "schemaName": null
    },
    "incomingClientIp": "::ffff:78.131.11.108"
  }
}
```

## 2. Key Object Mappings for Lilith Zero

When designing the `HookInput` translation layer in Lilith Zero (`copilot_studio.rs`), we must extract the following fields to ensure deterministic taint tracking and policy enforcement.

### A. Conversation/Session Tracking
Taint states in Lilith are tracked per-conversation.
- **Source Field:** `conversationMetadata.conversationId`
- **Example Value:** `"6dea8192-77ab-4305-8e75-c5c3472f43ce"`
- **Usage:** This string must be deterministically hashed (using HMAC-SHA256) by Lilith's `Crypto` module to generate the internal `SessionId`.

### B. Tool Identification
Policies map permissions against specific tools. **The `toolDefinition.id` is the single source of truth for runtime identification.**
- **Source Field:** `toolDefinition.id` (Primary)
- **Example Value:** `"cra65_otpdemo.action.MockActionsAPI-MockActionsAPI"`
- **Usage:** This becomes `tool_name` in the `HookInput` struct. The Cedar policy must match this identifier exactly. Note that `toolDefinition.name` (e.g., "Send-an-Email") is often different and unreliable for policy matching.

### C. Input Parameters (Arguments)
Tool arguments are evaluated for sensitive data (taints) or blocked patterns.
- **Source Field:** `inputValues`
- **Example Format:** A flat dictionary of string/object key-value pairs (`{"source": "locationG", "Range": "table_rangeG"}`).
- **Usage:** This maps to `tool_args` in the `HookInput` struct.

### D. Multi-Tenant / Agent Segregation
When running a shared Lilith Zero instance, policies may restrict tools per agent or environment.
- **Source Fields:** 
  - `conversationMetadata.agent.id` -> `agent_id`
  - `conversationMetadata.agent.environmentId` -> `environment_id`
  - `conversationMetadata.user.id` -> `user_id`
- **Usage:** These fields should be passed as context to the policy engine (e.g., `context.agent_id` in Cedar) to ensure tenants cannot cross-pollinate tool execution privileges.

## 3. Notable Observations
1. **Chat History Presence:** The payload contains the full LLM context window in `plannerContext.chatHistory`. This could be useful for advanced LLM prompt-injection detection in the future, though Lilith currently ignores it for sub-millisecond deterministic checks.
2. **IP Addresses:** The `conversationMetadata.incomingClientIp` is provided. This allows for conditional access policies (e.g., "deny if IP is not within corporate VPN").
3. **No Auth Token inside Payload:** The JSON does not contain the JWT. Auth is handled purely via the HTTP `Authorization: Bearer` header.
