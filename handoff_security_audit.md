# Handoff: Lilith Zero Security Webhook Audit & Hardening

## Overview
Lilith Zero is a security middleware for AI agents. This document summarizes the recent hardening of the **Copilot Studio Webhook Adapter**, which enables Lilith to act as an external threat detection provider for Microsoft Copilot Studio (Power Platform).

## Current Status
- **Architecture**: Rust-based Axum server implementing the [Copilot Studio External Security Webhook interface](https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers).
- **Core Engine**: Uses **Cedar** (formally verified policy language) for decision making.
- **State Management**: Recently upgraded to support **In-Memory Session Persistence**. Taints (e.g., `ACCESS_PRIVATE`, `UNTRUSTED_SOURCE`) now persist across multiple HTTP requests in the same conversation.

## Technical Context

### Key Files
- `lilith-zero/src/server/webhook.rs`: Main Axum router and handlers (`/validate`, `/analyze-tool-execution`).
- `lilith-zero/src/server/copilot_studio.rs`: Mapping logic between MS JSON payloads and Lilith internal types.
- `lilith-zero/src/engine/cedar_evaluator.rs`: Bridge between Rust and the Cedar Policy Engine.
- `lilith-zero/src/engine_core/security_core.rs`: Central logic for tool classification, taint tracking, and policy delegation.
- `examples/copilot_studio/policies/policy_5be3e14e...cedar`: The active security policy for the demo agent.

### Recent Fixes
1.  **Session Persistence**: Implemented a shared `RwLock<HashMap<String, SessionState>>` in `WebhookState`. The `conversation_id` is used as the key to ensure multi-turn taint tracking works in a stateless HTTP environment.
2.  **Context Aliasing**: Updated `CedarEvaluator` to provide `context.arguments` (alias for `context.args`) to match the naming convention used in the security policies.
3.  **Lethal Trifecta**: Added a global `forbid` rule in the Cedar policy to block tools classed as `EXFILTRATION` or `NETWORK` when both `ACCESS_PRIVATE` and `UNTRUSTED_SOURCE` taints are present.
4.  **Diagnostic Logging**: Added diagnostic strings to the webhook response to surface internal state (tool IDs, session IDs) during debugging.

## Identified Issues for Audit

### 1. "Indeterminate" Blocking (The "Indiscriminate Deny" Bug)
During recent tests, hit-to-endpoint `/analyze-tool-execution` resulted in all tool calls being blocked (Reason Code 1002: `STATIC_DENY`), even benign ones like `Search-Web`.
- **Hypothesis**: The Cedar policy uses `forbid` rules that access `context.arguments.url` or `context.arguments.code`. If a tool call (like `Search-Web`) does not contain these fields, Cedar may throw an evaluation error. In some configurations, an evaluation error in ANY rule can lead to a default `Deny` decision.
- **Action**: Audit the Cedar policy and wrap all attribute accesses in `.has("attribute")` checks to ensure the evaluator doesn't crash on missing fields.

### 2. Endpoint Routing Confusion
Tests occasionally return `{"isSuccessful": true, "status": "OK"}` even for tool calls.
- **Root Cause**: The Axum router maps the root `/` to the `handle_validate` handler for convenience. If the test script or environment configuration uses the base URL instead of the full `/analyze-tool-execution` path, it will receive the validation response (which always says "OK") instead of a security decision.
- **Action**: Ensure `taint_test.py` and production configurations point strictly to the specific endpoints.

### 3. Tool ID vs. Tool Name
The MS spec provides both `toolDefinition.id` (internal GUID) and `toolDefinition.name` (human-readable).
- **Current Mapping**: `copilot_studio.rs` maps `id` to `tool_name`.
- **Audit Task**: Confirm if the policy should use the human-readable `name` or the stable `id`. Currently, the policy is patched to include both, but a consistent standard is needed.

## Verification Plan
1.  **Local Testing**: Use `cargo test --features webhook` to run the integration suite.
2.  **Remote Testing**: Use `examples/copilot_studio/taint_test.py <URL> <AGENT_ID>`.
3.  **Log Review**: Check the container logs for "Successfully loaded Cedar PolicySet" and "Decision: ALLOW/DENY" entries.

## Security Goal
The final solution must be **Fail-Closed**. If the policy engine errors, if a session is unknown, or if no policy is loaded, Lilith MUST return `blockAction: true`.

---
*Document prepared by Antigravity for Security Audit Handoff.*
