# Implementation Plan: Enterprise Agent & Copilot Integrations

This document outlines the architecture and implementation steps required to extend Lilith Zero's hook capabilities. The goal is to support various Microsoft Copilot form factors (CodeBox, Windows VS Code, JetBrains, Copilot Studio, and standalone business agents) as requested by the enterprise client.

## 1. Context & Objectives

The recent implementation of the `lilith-zero hook` subcommand successfully intercepts Claude Code's `PreToolUse` and `PostToolUse` events via `stdin` and `stdout`, preserving state via the `PersistenceLayer`.

The enterprise client now requires this same policy-as-code enforcement to safeguard multiple AI implementations across their organization:
1. **Coding Assistant (Linux/Mac)**: VS Code + GitHub Copilot (GHCP) on VMs/CodeBoxes.
2. **Coding Assistant (Windows)**: VS Code + GHCP on developer laptops.
3. **JetBrains + GHCP**: Support for JetBrains IDEs (IntelliJ, etc.).
4. **Business Agents**: Containerized agents using the Copilot SDK.
5. **Copilot Studio**: Agents published via Power Platform.

This plan details how a new agent should structure these integrations, the files they must modify, and security considerations to prevent bypasses.

---

## 2. New Features to Implement

### Feature 1: Copilot-Compatible Hook Payloads
**Goal:** Adapt the existing `HookHandler` to parse Microsoft's specific JSON schema for agent hooks alongside the Claude schema.
*   **Information Source:** [Hooks configuration (GitHub Copilot reference)](https://docs.github.com/en/copilot/reference/hooks-configuration)
*   **Actionable Items:**
    *   Expand `HookInput` in `src/hook/mod.rs` (or create a `CopilotHookInput`) to support Copilot events (`sessionStart`, `preToolUse`, etc.). Note the camelCase convention vs Claude's PascalCase.
    *   Implement standard outputs (`{"allow": true}`, `{"allow": false, "reason": "..."}`) required by Copilot for stdout.

### Feature 2: Cross-Platform Execution Shims
**Goal:** Ensure the Lilith Zero binary can be seamlessly invoked by `hooks.json` on both Unix (bash) and Windows (PowerShell) systems.
*   **Information Source:** [Using hooks with GitHub Copilot agents](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/use-hooks)
*   **Actionable Items:**
    *   Create a `scripts/` or `wrappers/` directory.
    *   Write a standardized `hook-wrapper.sh` (for Mac/Linux/CodeBox) that pipes Copilot stdin to `lilith-zero hook` and formats output.
    *   Write a standardized `hook-wrapper.ps1` (for Windows laptops) that uses `ConvertTo-Json -Compress` to ensure single-line stdout compliance.

### Feature 3: Webhook Interface for Copilot Studio
**Goal:** Copilot Studio does not use standard local binaries or `hooks.json`. It requires a REST API webhook for `POST /validate` and `POST /analyze-tool-execution`.
*   **Information Source:** [Build a runtime threat detection system (developer interface)](https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers)
*   **Actionable Items:**
    *   Extend `lilith-zero` to optionally run as an HTTP server for webhooks, OR create a lightweight `axum` or `actix-web` sidecar (e.g., `src/server/webhook.rs`).
    *   Implement Entra ID (Bearer token) validation.
    *   Map the Copilot Studio REST payload to `SecurityCore::evaluate()`.

### Feature 4: Copilot SDK Business Agent Example
**Goal:** Demonstrate how a 2nd/3rd gen business agent can embed Lilith Zero validation in-process constraint without using shell hooks.
*   **Information Source:** [Pre-tool use hook (Copilot SDK)](https://docs.github.com/en/copilot/how-tos/copilot-sdk/use-hooks/pre-tool-use)
*   **Actionable Items:**
    *   Add a new example directory (`examples/copilot_sdk_agent/`).
    *   Show how to invoke `lilith-zero` from within the SDK's `onPreToolUse` callback (using the Python or TS SDK).

---

## 3. Implementation Blueprint for the Next Agent

### A. Repository Exploration
*   **Entry Point**: Start at `src/hook/mod.rs`. This file contains the current Claude Code integration.
*   **State Management**: Review `src/engine_core/persistence.rs`. The locking mechanism here is critical for Windows support (ensure `fs2` behaves nicely on NTFS/Windows execution policies).
*   **Policy Engine**: Review `src/engine_core/security_core.rs`. This is where all events must ultimately route, regardless of whether they come from Claude, Copilot VSCode, or Copilot Studio.

### B. Files to Modify

1.  **`src/hook/mod.rs` & `src/engine_core/events.rs`**
    *   *Task*: Refactor `HookInput` to support an enum or dynamic parser capable of identifying either Claude formats (`PreToolUse`, `session_id`) or Copilot formats (`preToolUse`, `session.id`, `tool.name`).
2.  **`src/main.rs`**
    *   *Task*: Add capabilities to the `hook` subcommand to format output securely based on the caller (e.g., `--format copilot` vs `--format claude`).
3.  **`Cargo.toml`**
    *   *Task*: If adding the webhook server for Copilot Studio, add HTTP dependencies (`axum`, `tokio-web`, etc.) behind a feature flag (e.g., `feature = "webhook"`).
4.  **`examples/`**
    *   *Task*: Expand the examples directory with configurations for VSCode (`.github/hooks/hooks.json`), JetBrains, and Windows setup instructions.

### C. Validation & Testing Requirements
1.  **Unit Tests**: Add tests in `src/hook/mod.rs` that feed mock Copilot `hooks.json` stdin strings to the parser and verify proper `SecurityCore` routing.
2.  **Integration Tests**: Create a `verify_copilot_hooks.sh` script (similar to the Claude one) that simulates a VS Code extension calling the binary.
3.  **Cross-Platform**: Ensure Windows tests (already defined in `Cargo.toml` under `cfg(windows)`) capture the new parser logic.

---

## 4. Security Considerations (Bypass Prevention)

As noted in the research, hooks are inherently client-side for IDEs. To maintain the strong security posture of Lilith:

*   **Enforcement Posture**: Lilith must remain **Fail-Closed**. If Copilot sends a malformed `preToolUse` payload, Lilith must output a `{"allow": false, "reason": "parsing failed"}` JSON string to instantly block the action.
*   **Pathing & Execution**: The generated wrappers (`hook-wrapper.sh`/`.ps1`) must strictly validate `cwd` and absolute paths to prevent untrusted workspace files from shadowing the binary.
*   **Studio Webhook Auth**: For the Copilot Studio REST webhook, hardcode strict validation of Microsoft Entra JWT tokens. Do not trust generic API keys for this endpoint.
*   **Defense-in-Depth Documentation**: The next agent *must* include an "ITRisk/ITSec Limitations" section in the primary documentation (as requested). Explicitly mandate that organizations deploy these hooks via managed endpoints, VS Code enterprise policies, or central image builds to prevent developers from disabling `.github/hooks`.

---
*Ready for the next agent to begin execution.*
