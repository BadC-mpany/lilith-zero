# Agent Learnings: Copilot Studio Integration Hardening (May 2026)

This document captures critical architectural insights and technical "walls" encountered during the hardening of the Lilith Zero security middleware for Copilot Studio (PVA) Threat Detection Webhooks.

## 1. The Tool ID Mismatch Wall

### The Problem
During initial deployment, custom tools (e.g., 'Send-an-Email') were consistently blocked by Lilith's policy engine, even when policies seemed to exist. The audit logs showed a `DENY` decision because the `resource` identifier didn't match any permitted rule.

### The Learning
Copilot Studio payloads contain two identification fields in `toolDefinition`:
- `name`: A human-readable display name (e.g., `"Send-an-Email"`).
- `id`: A complex identifier (e.g., `"cra65_otpdemo.action.MockActionsAPI-MockActionsAPI"`).

**Crucially, the `id` is the stable runtime identifier used by the platform.** The `name` is often just a display string and can change or be truncated. Lilith Zero must use `toolDefinition.id` as the primary key for policy evaluation.

### The Fix
1.  **Rust Core**: Hardened `to_hook_input` in `copilot_studio.rs` to map `tool_definition.id` to the evaluation identifier.
2.  **Extraction Logic**: Updated `extract_tools.py` to reconstruct these IDs from the bot template by:
    - Extracting the publisher prefix from `connectionReference`.
    - Applying the exact slugification logic (Pascal-Hyphen-Case, joining parts).

## 2. Infrastructure & Deployment Gotchas

### Azure App Service Persistence
- Lilith tracks session state (taints) in a local `sessions/` directory.
- On Azure App Service, ensure this directory is in a persistent path (like `/home/lilith/sessions`) or configured via environment variables to avoid losing taint state across container restarts.

### Restart Transition Timing
- `az webapp restart` is not instantaneous. 
- There is a "phantom window" where the old container may still serve requests while the new one is starting. Always verify the `X-Lilith-Version` header (or similar metadata) when running integration tests immediately after a deployment.

### CLI vs Environment Configuration
- When running `lilith-zero serve`, the `--policy <DIR>` flag is the most robust way to enable multi-tenant Cedar routing.
- The server will monitor this directory for files named `policy_<AGENT_ID>.cedar`.

## 3. Test Suite Integrity
- When changing core evaluation logic (like switching from `name` to `id`), you **must** update the integration tests in `tests/webhook_tests.rs`.
- The test harness often uses a `tool-` prefix in its mock `id`s. If the policies in the tests aren't updated to include this prefix, the entire test suite will fail closed, simulating a catastrophic security regression.

## 4. Key Artifacts
- `examples/copilot_studio/extract_tools.py`: The source of truth for tool discovery.
- `lilith-zero/src/server/copilot_studio.rs`: The translation layer for PVA payloads.
- `docs/azure-deployment-guide.md`: The production deployment recipe.
