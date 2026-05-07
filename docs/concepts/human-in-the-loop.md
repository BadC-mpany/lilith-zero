# Human-in-the-Loop (HITL) Approval

Technical requirements for per-interface human approval in Lilith Zero.
**Status:** Research complete. Not yet implemented.

---

## Core Design

### Cedar policy syntax

Cedar is binary (permit/forbid). HITL is expressed as a `permit` rule with a `@human_approval("true")` annotation. Lilith's evaluator reads the annotation and upgrades the internal decision from `Allow` to `HumanApproval`.

```cedar
@id("require_approval:send_external_email")
@reason("Sending email to external recipient requires human approval")
@human_approval("true")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"Send-an-Email"
};
```

### Internal decision type

```rust
pub enum SecurityDecision {
    Allow,
    AllowWithTransforms { .. },
    Deny { reason: String, error_code: i32 },
    HumanApproval { reason: String, timeout_secs: u64 },  // NEW
}
```

### Timeout behavior

Default: **fail-closed** (treat expired approval as Deny). Configurable per deployment to fail-open (treat as Allow with audit log entry). The timeout value comes from the Cedar rule annotation or a global config default.

---

## Interface: Claude Code (hooks)

**Status: SUPPORTED — uses native Claude Code permission UI**

### Mechanism

Return `permissionDecision: "ask"` from the PreToolUse hook. Claude Code shows its native terminal permission dialog — the **same dialog Claude Code already uses for all tool approvals**. No separate UI to build.

**What the user sees in the terminal:**
```
╭─ Tool Permission Request ──────────────────────────╮
│ Claude wants to use: Send-an-Email                  │
│                                                     │
│ to: external@partner.com                           │
│                                                     │
│ [Lilith] Sending email to external recipient        │
│          requires human approval                    │
│                                                     │
│ (a)llow  (d)eny  (A)lways allow  View rule         │
╰────────────────────────────────────────────────────╯
```

User options:
- **Allow** — tool executes this time
- **Deny** — tool blocked, Claude sees the reason
- **Always allow** — executes + adds a permission rule (⚠️ bypasses Lilith for future calls)
- **View rule** — shows the rule that would be created

Hook stdout that triggers this:
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "Sending email to external recipient requires human approval"
  }
}
```

### Headless / Agent SDK flows: `defer`

For non-interactive (`claude -p`) and Agent SDK usage, return `permissionDecision: "defer"`. Claude Code exits the session with `stop_reason: "tool_deferred"` and persists the pending tool call to disk. An external system collects the human's answer (via any UI: email, Teams, Slack, web form) and resumes:

```bash
claude -p --resume <session-id> --permission-mode default
```

On resume, the same PreToolUse hook fires. Lilith returns `allow` with the answer in `updatedInput`.

**State persistence:** Claude Code handles session persistence on disk. Lilith needs no additional state store.

**Requires:** Claude Code v2.1.89+. Only works with single tool calls per turn (not parallel).

### Sources

- [Claude Code Hooks reference](https://code.claude.com/docs/en/hooks) — `permissionDecision` values, defer semantics
- [Handle approvals — Agent SDK](https://code.claude.com/docs/en/agent-sdk/user-input) — `canUseTool` callback, defer in TS SDK

---

## Interface: VS Code Copilot (hooks)

**Status: SUPPORTED — uses native VS Code permission UI**

### Mechanism

Same hook JSON output as Claude Code — return `permissionDecision: "ask"`. VS Code shows a native permission UI (inline confirmation in the chat/agent pane — exact visual not documented, but functionally: the agent pauses and waits for user confirmation before executing the tool).

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "Sending email to external recipient requires human approval"
  }
}
```

**Supported values:** `allow`, `deny`, `ask`. `defer` is **not supported** in VS Code.

**`updatedInput` supported:** yes (with caveat — if schema mismatch, it is ignored).

### Sources

- [Agent hooks in Visual Studio Code](https://code.visualstudio.com/docs/copilot/customization/hooks) — permission decision values, ask behavior

---

## Interface: MCP Middleware

**Status: SUPPORTED — uses MCP elicitation protocol (spec 2025-11-25)**

### Mechanism

When Lilith's MCP proxy decides `HumanApproval`, it sends an `elicitation/create` request upstream to the MCP client. The client surfaces a form to the user. The user responds (`accept`, `decline`, `cancel`). Lilith then allows or denies the tool call based on the response.

**Capability check first:** Lilith MUST check that the client declared `"elicitation"` capability during initialization. If not declared, Lilith MUST fail-closed (deny) and return a JSON-RPC error explaining the client doesn't support approval requests.

**Wire protocol:**

Server → Client request:
```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "method": "elicitation/create",
  "params": {
    "mode": "form",
    "message": "Sending email to external recipient requires human approval. Allow?",
    "requestedSchema": {
      "type": "object",
      "properties": {
        "decision": {
          "type": "string",
          "title": "Decision",
          "enum": ["Allow", "Deny"],
          "description": "Allow or deny this tool call"
        }
      },
      "required": ["decision"]
    }
  }
}
```

Client → Server response:
```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "result": {
    "action": "accept",
    "content": { "decision": "Allow" }
  }
}
```

Response `action` values:
- `accept` + `content.decision == "Allow"` → Lilith returns `Allow`
- `accept` + `content.decision == "Deny"` → Lilith returns `Deny`
- `decline` — user explicitly declined → Lilith returns `Deny`
- `cancel` — user dismissed → Lilith returns `Deny` (fail-closed) or `Allow` (if fail-open configured)

**State persistence:** none needed — the MCP connection stays open; the elicitation is a synchronous blocking call within the connection.

**Timeout:** configurable; on timeout → fail-closed Deny with error message to client.

**Client support:** Not all MCP clients implement elicitation yet. Check `capabilities.elicitation` in the `initialize` response. Clients that do not declare this capability receive a `Deny` with a descriptive error:
> `"Human approval required but MCP client does not support elicitation (capabilities.elicitation not declared). Tool call denied. Upgrade your MCP client to enable approval flows."`

### Sources

- [MCP Elicitation specification (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation)

---

## Interface: Claude Agent SDK

**Status: SUPPORTED — application implements approval UI via `canUseTool` callback**

### Mechanism

The Agent SDK exposes a `canUseTool` async callback that pauses execution until the application returns allow/deny. When Lilith signals `HumanApproval`, the application's `canUseTool` implementation is responsible for surfacing the approval to the user in whatever UI makes sense (terminal, web form, email, Slack).

**The SDK stays paused indefinitely** until the callback returns. No timeout from the SDK itself.

The `PermissionRequest` hook in the Agent SDK can also be used to send notifications (Slack, email, push) when the approval request fires, allowing the human to respond asynchronously while the process waits.

**Python:**
```python
async def can_use_tool(tool_name: str, input_data: dict, context) -> PermissionResultAllow | PermissionResultDeny:
    # Lilith has already decided HumanApproval for this tool
    # Application presents the decision to the user
    print(f"\n⚠ Lilith requires human approval for: {tool_name}")
    print(f"Reason: {context.lilith_reason}")  # passed via additionalContext
    response = input("Allow? (y/n): ")
    if response.lower() == "y":
        return PermissionResultAllow(updated_input=input_data)
    return PermissionResultDeny(message="Human denied the action")
```

**TypeScript (with defer for long-running approvals):**
```typescript
canUseTool: async (toolName, input, options) => {
  // For async approval (email/Teams/etc.), return defer via hook
  // The process exits, external system collects approval, resumes session
  // See Claude Code "defer" section above
}
```

**State persistence:** in-memory is sufficient for synchronous flows (callback stays open). For async flows using `defer` (TypeScript SDK only), Claude Code handles session persistence on disk.

### Sources

- [Handle approvals and user input — Agent SDK](https://code.claude.com/docs/en/agent-sdk/user-input)
- [Configure permissions — Agent SDK](https://code.claude.com/docs/en/agent-sdk/permissions)

---

## Interface: GitHub Copilot CLI (hooks)

**Status: NOT YET SUPPORTED**

### Why not

The GH Copilot CLI hook system does not document `permissionDecision` values (`ask`, `defer`). Only exit codes are documented (0 = proceed, 2 = block). There is no native approval dialog in the CLI. The only mechanism Lilith could use is:

1. Exit code 2 + stderr message with instructions (e.g., a URL to an approval page) — the model receives the message but the human must take external action
2. A blocking `read` call inside the hook bash script — technically works (shell script blocks until user types) but is rough UX

Neither option provides a native integrated experience comparable to Claude Code's `"ask"`. Implementing HITL here requires either building a custom terminal prompt in the hook script or directing users to an external approval URL.

### Future options when supported

- Option A: blocking `read` prompt in hook shell script (simple, in-terminal, no dependencies)
- Option B: open a browser/external URL for approval, exit 2 until approved (async, better for secure contexts)
- Option C: integrate with GitHub Actions approval gates if running in that environment

### Sources

- [Using hooks with GitHub Copilot agents](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/use-hooks)

---

## Interface: Copilot Studio (threat detection webhook)

**Status: NOT YET SUPPORTED**

### Why not

The `POST /analyze-tool-execution` endpoint has a **hard 1-second response timeout**. If Lilith doesn't respond within 1 second, Copilot Studio defaults to Allow. Synchronous human-in-the-loop is structurally impossible through this API.

### Options when addressing this in the future

**Option A — Deny + signal (recommended starting point)**
Lilith returns `blockAction: true` with a specific `reasonCode` (e.g., `1006 = HUMAN_APPROVAL_REQUIRED`) and a `reason` string containing instructions. The Copilot Studio agent's topic/dialog is designed to catch this code and trigger a Power Automate multistage approval flow. On human approval, the Copilot Studio agent re-initiates the tool call. Requires agent topic design to cooperate with Lilith.

```json
{
  "blockAction": true,
  "reasonCode": 1006,
  "reason": "Human approval required for Send-an-Email to external recipient. Your admin has been notified. The request will be re-submitted after approval.",
  "diagnostics": "{\"approval_required\":true,\"rule\":\"require_approval:send_external_email\"}"
}
```

**Option B — Agent-level confirmation topics**
Configure specific Copilot Studio agent topics to include a human confirmation step before calling certain tools. Lilith's Cedar policy documents which tools need this, but enforcement is agent-side. Lilith still blocks unapproved calls as a safety net. No webhook-level changes needed.

**Option C — Human supervision (computer-use agents only)**
Copilot Studio has a native human supervision feature for computer-use agents. Designated reviewers receive email/inline review requests when the agent flags a concern. However, this is limited to computer-use agents and cannot be triggered by the threat detection webhook.

**Option D — Power Automate multistage approvals**
The agent flow triggers a Power Automate approval workflow (Human review connector). Human approvers respond via Teams, Outlook, or the Power Automate portal. Requires Option A (deny + signal) as the trigger mechanism from Lilith's webhook.

### Sources

- [Build a runtime threat detection system](https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers) — 1-second timeout, response schema
- [Multistage and AI approvals in agent flows](https://learn.microsoft.com/en-us/microsoft-copilot-studio/flows-advanced-approvals)
- [Human supervision of computer use](https://learn.microsoft.com/en-us/microsoft-copilot-studio/human-supervision-computer-use)

---

## Summary

| Interface | Status | Mechanism | Native UI |
|---|---|---|---|
| Claude Code (interactive) | Supported | `permissionDecision: "ask"` | ✅ Native terminal dialog |
| Claude Code (headless `-p`) | Supported | `permissionDecision: "defer"` | External (app implements) |
| VS Code Copilot | Supported | `permissionDecision: "ask"` | ✅ Native VS Code UI |
| MCP middleware | Supported | `elicitation/create` (form mode) | Client-defined |
| Claude Agent SDK | Supported | `canUseTool` callback | App-defined |
| GitHub Copilot CLI | Not yet | — | None native |
| Copilot Studio | Not yet | — | Deny + signal pattern |
