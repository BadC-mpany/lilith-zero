# Human-in-the-Loop Approval: Implementation Plan

**Status:** Approved for implementation. No code changes made yet.
**TDD:** All interfaces require tests before implementation code.

---

## Goals

Add a first-class `HumanApproval` decision type to the Lilith Zero security pipeline. When a Cedar policy carries `@human_approval("true")`, execution is paused and a human decides at runtime.

## Non-Goals (explicitly out of scope)

### GitHub Copilot CLI

No native `permissionDecision` mechanism exists in GH CLI hooks. Only exit codes are documented. No interactive approval UI is available. Lilith will return a structured deny with a clear error:

```
[Lilith] Human approval required but GitHub Copilot CLI does not support 
interactive approval. Tool call denied. Use Claude Code or VS Code for 
human-in-the-loop policies.
```

This is a standard `SecurityDecision::Deny` — no `HumanApproval` variant is emitted. The Cedar `@human_approval("true")` annotation is treated as a `Deny` in the GH CLI hook adapter.

### Copilot Studio (threat detection webhook)

The `POST /analyze-tool-execution` API has a hard 1-second timeout. Synchronous human approval is structurally impossible. Lilith will return:

```json
{
  "blockAction": true,
  "reasonCode": 1006,
  "reason": "Human approval required but Copilot Studio threat detection webhook cannot support interactive approval (1-second timeout constraint). See policy rule: <rule_id>."
}
```

`reasonCode: 1006` is reserved for `HUMAN_APPROVAL_REQUIRED`. The Copilot Studio agent's topic design can catch this code and trigger a Power Automate approval flow as a separate concern. Future work, not in this plan.

---

## Cedar Policy Syntax

### New annotations

| Annotation | Required | Description |
|---|---|---|
| `@human_approval("true")` | Yes (on any `permit` rule) | Marks this permit rule as requiring runtime human approval |
| `@approval_prompt("...")` | Yes when `@human_approval("true")` | Human-facing text shown in the approval UI |
| `@timeout_secs("120")` | Optional | Seconds before fail-closed. Default: 120. Overrides global config |
| `@reason("...")` | Recommended | Post-denial reason shown in audit log if approval is declined |

### Example policy

```cedar
// Tool requires human approval before execution.
// Cedar evaluates this as permit, Lilith upgrades to HumanApproval.
@id("require_approval:send_external_email")
@human_approval("true")
@approval_prompt("Send-an-Email targets an external recipient. Allow this tool call?")
@reason("Email to external recipient blocked: human approval was not granted")
@timeout_secs("300")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"Send-an-Email"
};

// Trifecta case: require approval only when both taints active
@id("require_approval:high_risk_search_after_access")
@human_approval("true")
@approval_prompt("Agent has read private data and wants to search the web. This pattern has elevated exfiltration risk. Allow?")
@reason("Web search after private data access blocked pending human review")
@timeout_secs("120")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"Search-Web") &&
    context.taints.contains("ACCESS_PRIVATE")
};
```

### Annotation extraction order in the evaluator

For an Allow decision, iterate `response.diagnostics().reason()` (the set of matching permit policy IDs). For the first policy that has `@human_approval("true")`:
1. Read `@approval_prompt` → `approval_prompt: String`
2. Read `@timeout_secs` → parse as `u64`, default 120 if absent or unparseable
3. Read `@reason` → `reason: String`, default `"Tool requires human approval"` if absent
4. Produce `Decision::PendingHumanApproval { reason, approval_prompt, timeout_secs }`

If no policy in the Allow set carries `@human_approval("true")`, proceed as normal Allow.

---

## Architecture: Core Changes

### 1. `engine_core/models.rs` — Internal `Decision` enum

Add the `PendingHumanApproval` variant:

```rust
pub enum Decision {
    Allowed,
    AllowedWithSideEffects {
        taints_to_add: Vec<String>,
        taints_to_remove: Vec<String>,
    },
    Denied { reason: String },
    // NEW — produced when a permit rule carries @human_approval("true").
    // Cedar evaluates the rule as Allow; Lilith upgrades it here.
    PendingHumanApproval {
        reason: String,          // post-denial text (from @reason)
        approval_prompt: String, // human-facing UI text (from @approval_prompt)
        timeout_secs: u64,       // fail-closed timeout (from @timeout_secs)
    },
}
```

### 2. `engine_core/events.rs` — Public `SecurityDecision` enum

Add the `HumanApproval` variant:

```rust
pub enum SecurityDecision {
    Allow,
    AllowWithTransforms {
        taints_to_add: Vec<String>,
        taints_to_remove: Vec<String>,
        output_transforms: Vec<OutputTransform>,
    },
    Deny { reason: String, error_code: i32 },
    // NEW — produced from Decision::PendingHumanApproval.
    // Each interface adapter maps this to its native approval mechanism.
    // If the interface does not support approval, treat as Deny.
    HumanApproval {
        reason: String,          // used in audit log on denial
        approval_prompt: String, // shown to the human in the UI
        timeout_secs: u64,       // adapter-level timeout before fail-closed
    },
}
```

### 3. `engine/cedar_evaluator.rs` — Evaluator changes

**This section is written for colleague review. Changes are localized to the Allow branch.**

Current flow in the Allow path (inside `security_core.rs`, the `tools/call` evaluation block):

```rust
if response.decision() == CedarDecision::Allow {
    let mut taints_to_add = vec![];
    let mut taints_to_remove = vec![];
    for policy_id in response.diagnostics().reason() {
        // read @id annotation for taint directives
        ...
    }
    if taints_to_add.is_empty() && taints_to_remove.is_empty() {
        Ok(Decision::Allowed)
    } else {
        Ok(Decision::AllowedWithSideEffects { taints_to_add, taints_to_remove })
    }
}
```

**New flow — same block, extended:**

After the existing taint collection loop, add a second pass over `response.diagnostics().reason()` to check for `@human_approval`:

```rust
if response.decision() == CedarDecision::Allow {
    let mut taints_to_add = vec![];
    let mut taints_to_remove = vec![];
    let mut human_approval: Option<(String, String, u64)> = None; // (reason, prompt, timeout)

    for policy_id in response.diagnostics().reason() {
        // --- existing taint logic (unchanged) ---
        let effective_id = cedar_eval
            .get_policy_annotation(policy_id, "id")
            .unwrap_or_else(|| policy_id.to_string());
        if let Some(tag) = effective_id.strip_prefix("add_taint:") { .. }
        else if let Some(tag) = effective_id.strip_prefix("remove_taint:") { .. }

        // --- NEW: check for @human_approval annotation ---
        if cedar_eval.get_policy_annotation(policy_id, "human_approval").as_deref() == Some("true") {
            // Only the first matching policy's annotations are used.
            if human_approval.is_none() {
                let prompt = cedar_eval
                    .get_policy_annotation(policy_id, "approval_prompt")
                    .unwrap_or_else(|| "This tool requires human approval".to_string());
                let reason = cedar_eval
                    .get_policy_annotation(policy_id, "reason")
                    .unwrap_or_else(|| "Tool requires human approval".to_string());
                let timeout = cedar_eval
                    .get_policy_annotation(policy_id, "timeout_secs")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(120);
                human_approval = Some((reason, prompt, timeout));
            }
        }
    }

    // Human approval takes precedence over all other Allow outcomes.
    // Taint side-effects from OTHER policies in the allow set are NOT applied
    // until the human grants approval (they are applied on the resumed Allow path).
    if let Some((reason, approval_prompt, timeout_secs)) = human_approval {
        return Ok(Decision::PendingHumanApproval { reason, approval_prompt, timeout_secs });
    }

    if taints_to_add.is_empty() && taints_to_remove.is_empty() {
        Ok(Decision::Allowed)
    } else {
        Ok(Decision::AllowedWithSideEffects { taints_to_add, taints_to_remove })
    }
}
```

**Also change: `process_evaluator_decision()`** in `security_core.rs`

Add the new arm:

```rust
Decision::PendingHumanApproval { reason, approval_prompt, timeout_secs } => {
    self.log_audit("HumanApprovalRequested", json!({
        "tool_name": tool_name,
        "approval_prompt": approval_prompt,
        "timeout_secs": timeout_secs,
    }));
    SecurityDecision::HumanApproval { reason, approval_prompt, timeout_secs }
}
```

**Colleague review checklist:**
- [ ] `human_approval` check is inside the Allow branch only (not in the Deny branch)
- [ ] Taint side-effects are NOT applied when `PendingHumanApproval` is returned
- [ ] Audit log entry is emitted for every `HumanApproval` decision
- [ ] The `@human_approval` annotation is checked AFTER taint collection (so the full taint list is available for context if needed)
- [ ] Only the FIRST matching policy's annotations are read (earliest in iteration order of `diagnostics().reason()`)
- [ ] `get_policy_annotation(policy_id, "human_approval")` checks for the value `"true"` (case-sensitive)

### 4. `engine_core/telemetry.rs` — TelemetryHook

Add `on_human_approval_requested`:

```rust
/// Called when a Cedar policy requires human approval before a tool proceeds.
///
/// The hook implementation should surface this to the operator's monitoring
/// system (Sentinel, Slack, email) so approvals can be tracked.
fn on_human_approval_requested(
    &self,
    session_id: &str,
    tool_name: &str,
    approval_prompt: &str,
    timeout_secs: u64,
) {
    let _ = (session_id, tool_name, approval_prompt, timeout_secs);
}

/// Called when a human approval was granted (decision: allow).
fn on_human_approval_granted(&self, session_id: &str, tool_name: &str) {
    let _ = (session_id, tool_name);
}

/// Called when a human approval was denied or timed out.
fn on_human_approval_denied(&self, session_id: &str, tool_name: &str, reason: &str) {
    let _ = (session_id, tool_name, reason);
}
```

---

## Architecture: Interface-Specific Changes

### Shared: `hook/mod.rs`

`handle_pre_tool` currently returns `Result<(i32, Option<String>)>`. The `HumanApproval` case needs to emit JSON to stdout (not just an exit code). The return type must carry the JSON payload:

```rust
pub struct HookDecision {
    pub exit_code: i32,
    /// If Some, write this JSON to stdout before exiting.
    /// Used for permissionDecision payloads (ask, defer).
    pub stdout_json: Option<serde_json::Value>,
    /// Deny reason (for audit/stderr), if applicable.
    pub deny_reason: Option<String>,
}
```

`handle_with_reason` return type changes to `Result<HookDecision>`.

`handle_pre_tool` produces a `HookDecision`:
- `Allow` → `{ exit_code: 0, stdout_json: None, deny_reason: None }`
- `Deny` → `{ exit_code: 2, stdout_json: None, deny_reason: Some(reason) }`
- `HumanApproval` → varies by adapter (see below)

The top-level binary (`main.rs`) reads `HookDecision` and:
1. If `stdout_json` is `Some`, serialise it to stdout
2. If `deny_reason` is `Some`, write to stderr
3. `std::process::exit(exit_code)`

### Interface A: Claude Code (interactive `"ask"`)

When `SecurityDecision::HumanApproval`:

```rust
HookDecision {
    exit_code: 0,
    stdout_json: Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": approval_prompt,
        }
    })),
    deny_reason: None,
}
```

**"Always allow" bypass note:**
The hook fires on every call — Lilith's Cedar evaluation always runs. However, if the user clicks "Always allow" in Claude Code's permission dialog, Claude Code writes an **allow rule** to settings. On subsequent calls:
- Lilith's hook fires and evaluates the Cedar policy (producing `HumanApproval` again)
- The hook returns `permissionDecision: "ask"` again
- Claude Code evaluates the allow rule (deny > ask > allow precedence)
- The allow rule silently skips the prompt → tool proceeds without human confirmation

This is a known limitation. For Bash commands, "Always allow" is permanent. For file edits, it is per-session. This is acceptable behaviour — a user who explicitly chooses to trust a tool pattern bypasses the approval gate.

```rust
// SECURITY: Claude Code's "Always allow" creates an allow permission rule that
// silently bypasses the human approval prompt on future calls, even though this
// hook still fires and Lilith's Cedar evaluation still runs. The allow rule takes
// precedence over the hook's "ask" decision (deny > ask rules > allow rules > hook ask).
// This is acceptable: a user who grants "Always allow" is making an explicit trust decision.
// "Always allow" for Bash is permanent; for file edits it is per-session only.
```

### Interface B: Claude Code headless (`"defer"`)

For programmatic flows using `claude -p` (requires Claude Code ≥ v2.1.89, single tool call per turn):

```rust
HookDecision {
    exit_code: 0,
    stdout_json: Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "defer",
        }
    })),
    deny_reason: None,
}
```

Claude Code exits with `stop_reason: "tool_deferred"`. The external system resumes with `claude -p --resume <session_id>`. On resume, the hook fires again. At that point the hook reads whether the human approved (from the in-memory approval store, see State section) and returns `"allow"` or `"deny"`.

**Detection of interactive vs headless:** Check the `CLAUDE_CODE_ENTRYPOINT` environment variable or use a config flag `lilith_hitl_mode: "ask" | "defer" | "auto"`. In `"auto"` mode, Lilith detects headless by checking if stdin is a TTY: `!std::io::stdin().is_terminal()` (using `std::io::IsTerminal`).

### Interface C: VS Code Copilot hooks

Identical JSON output to Claude Code `"ask"`. No `"defer"` support in VS Code.

```rust
HookDecision {
    exit_code: 0,
    stdout_json: Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": approval_prompt,
        }
    })),
    deny_reason: None,
}
```

### Interface D: MCP Middleware

When `SecurityDecision::HumanApproval` is produced during `tools/call` evaluation in `mcp/server.rs`:

**Step 1: Capability check.** Read the client's declared capabilities from the `initialize` handshake. If `capabilities.elicitation` is absent or empty:
- Return a JSON-RPC error to the agent, fail-closed
- Error message: `"Human approval required but MCP client does not support elicitation (capabilities.elicitation not declared). Upgrade your MCP client. Tool call denied."`
- Error code: `-32002` (standard MCP RequestFailed) or a Lilith-defined code

**Step 2: Send elicitation.** If client supports elicitation (`form` mode):

```json
{
  "jsonrpc": "2.0",
  "id": <new_id>,
  "method": "elicitation/create",
  "params": {
    "mode": "form",
    "message": "<approval_prompt>",
    "requestedSchema": {
      "type": "object",
      "properties": {
        "decision": {
          "type": "string",
          "title": "Decision",
          "enum": ["Allow", "Deny"],
          "description": "Allow or deny execution of this tool call"
        }
      },
      "required": ["decision"]
    }
  }
}
```

**Step 3: Handle response.**

| Response | Action |
|---|---|
| `{ action: "accept", content: { decision: "Allow" } }` | Forward the tool call to upstream |
| `{ action: "accept", content: { decision: "Deny" } }` | Return JSON-RPC deny error to agent |
| `{ action: "decline" }` | Return JSON-RPC deny error (explicit human rejection) |
| `{ action: "cancel" }` | Fail-closed by default (Deny), fail-open if configured |
| No response within `timeout_secs` | Fail-closed Deny; log timeout in audit |

**Timeout:** implemented with `tokio::time::timeout` around the elicitation request. The timeout value is taken from the Cedar annotation (`@timeout_secs`), falling back to the global `config.hitl_timeout_secs` default (120s).

**State persistence:** None needed. The MCP connection stays open. The elicitation `id` is unique per request. The blocking `tokio::time::timeout` + channel handles the wait.

### Interface E: Claude Agent SDK

The Agent SDK exposes a `canUseTool` callback that blocks until the application returns. Lilith signals `HumanApproval` via the hook layer. The application developer is responsible for the approval UI.

Lilith provides a clean API surface for developers to hook into:

**`LilithApprovalRequest` struct** (emitted by Lilith when HumanApproval):

```rust
pub struct LilithApprovalRequest {
    pub session_id: String,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub approval_prompt: String,   // from @approval_prompt annotation
    pub reason: String,            // from @reason annotation (shown on deny)
    pub timeout_secs: u64,
}

pub enum LilithApprovalDecision {
    Approved,
    Denied { reason: String },
}
```

**Option A — Simple terminal handler** (Lilith provides as a default):

```rust
pub struct TerminalApprovalHandler;

impl TerminalApprovalHandler {
    pub async fn request(&self, req: &LilithApprovalRequest) -> LilithApprovalDecision {
        // Prints to terminal and blocks on stdin
        eprintln!("[Lilith] Human approval required");
        eprintln!("  Tool: {}", req.tool_name);
        eprintln!("  Prompt: {}", req.approval_prompt);
        eprint!("  Allow? [y/N]: ");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap_or_default();
        if line.trim().eq_ignore_ascii_case("y") {
            LilithApprovalDecision::Approved
        } else {
            LilithApprovalDecision::Denied { reason: "User denied".to_string() }
        }
    }
}
```

**Option B — Custom handler trait** (developer implements):

```rust
#[async_trait]
pub trait ApprovalHandler: Send + Sync {
    async fn request(&self, req: &LilithApprovalRequest) -> LilithApprovalDecision;
}
```

Registered on the `HookHandler`:

```rust
pub fn with_approval_handler(mut self, handler: Arc<dyn ApprovalHandler>) -> Self {
    self.approval_handler = Some(handler);
    self
}
```

When `HumanApproval` is returned and an `approval_handler` is set, `handle_pre_tool` calls `handler.request(...)`, waits for the result, and translates to allow/deny.

If no `approval_handler` is set: fail-closed (treat as Deny) with a clear log message: `"HumanApproval decision but no approval_handler configured. Failing closed."`

---

## State: In-Memory Approval Store

For the `defer` resume path (headless Claude Code), Lilith needs to know the human's answer when the session resumes. This is stored in memory:

```rust
// Global or per-HookHandler
pub struct PendingApprovals {
    store: Arc<Mutex<HashMap<String, LilithApprovalDecision>>>,
    // key: session_id
}
```

On `defer`: the hook exits. There is no state to store — Claude Code persists the session on disk. On resume, the hook fires again. At this point, the external system (the one that drove the resume) must have signalled the decision before calling `claude -p --resume`. The mechanism:

- The external system writes the decision to a well-known temp file: `/tmp/lilith-approval-<session_id>.json`
- Lilith's hook reads this file on the resume call, returns `allow` or `deny`, then deletes the file
- Simple, no daemon required, works across process restarts

This is the simplest possible approach: one temp file per deferred session. No Redis, no database, no daemon. The file path uses `session_id` which is already filesystem-safe (sanitized by `PersistenceLayer::sanitize_session_id`).

For MCP and Agent SDK: in-memory is sufficient (the call blocks within the same process).

---

## Timeout Handling

```rust
pub struct HitlConfig {
    /// Default timeout when @timeout_secs annotation is absent.
    /// Can be set via environment variable LILITH_HITL_TIMEOUT_SECS.
    pub default_timeout_secs: u64,  // default: 120
    /// Behaviour on timeout: Deny (fail-closed) or Allow (fail-open).
    pub timeout_fallback: HitlFallback,
}

pub enum HitlFallback {
    Deny,   // default
    Allow,  // configurable per deployment
}
```

On timeout:
- Emit audit log: `{ event_type: "HumanApprovalTimeout", tool_name, timeout_secs }`
- Call `on_human_approval_denied` telemetry hook with reason `"timeout"`
- Return `Deny` (or `Allow` if `timeout_fallback = Allow`)

---

## Testing Plan

**Principle:** One Cedar policy file used across all tests. TDD — tests written before implementation.

### Shared test policy (`tests/fixtures/hitl_policy.cedar`)

```cedar
// ── Human approval: simple case ──────────────────────────────────────────────
@id("require_approval:test_tool")
@human_approval("true")
@approval_prompt("test_tool requires human approval. Allow?")
@reason("test_tool was denied pending human approval")
@timeout_secs("10")
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"test_hitl_tool"
);

// ── Human approval: taint-conditional ────────────────────────────────────────
@id("require_approval:after_private_access")
@human_approval("true")
@approval_prompt("High-risk: private data + web search. Allow?")
@reason("Search blocked: private data taint requires approval")
@timeout_secs("5")
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"search_web"
) when {
    context.taints.contains("ACCESS_PRIVATE")
};

// ── Regular allow (control) ───────────────────────────────────────────────────
@id("allow:read_tool")
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"read_tool"
);

// ── Regular deny (control) ───────────────────────────────────────────────────
@id("deny:blocked_tool")
@reason("blocked_tool is always denied")
forbid(
    principal,
    action == Action::"tools/call",
    resource == Resource::"blocked_tool"
);

// ── Human approval with missing @approval_prompt (tests default fallback) ────
@id("require_approval:no_prompt_tool")
@human_approval("true")
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"no_prompt_tool"
);
```

---

### Unit tests: Cedar evaluator (`tests/cedar_hitl_unit.rs`)

Goal: verify the evaluator produces `SecurityDecision::HumanApproval` from annotated Cedar policies.

| Test | Input | Expected |
|---|---|---|
| `hitl_annotation_produces_human_approval` | `test_hitl_tool`, no taint | `SecurityDecision::HumanApproval { approval_prompt: "test_tool requires human approval. Allow?", .. }` |
| `hitl_approval_prompt_text_is_from_annotation` | `test_hitl_tool` | `approval_prompt` matches `@approval_prompt` annotation exactly |
| `hitl_reason_text_is_from_annotation` | `test_hitl_tool` | `reason` matches `@reason` annotation |
| `hitl_timeout_from_annotation` | `test_hitl_tool` | `timeout_secs == 10` |
| `hitl_default_timeout_when_annotation_absent` | `no_prompt_tool` | `timeout_secs == 120` (global default) |
| `hitl_default_prompt_when_annotation_absent` | `no_prompt_tool` | `approval_prompt` equals the hardcoded default string |
| `hitl_with_taint_triggers_conditional_rule` | `search_web`, taint = `["ACCESS_PRIVATE"]` | `SecurityDecision::HumanApproval` |
| `hitl_without_taint_skips_conditional_rule` | `search_web`, taint = `[]` | `SecurityDecision::Allow` (no taint = no approval needed) |
| `regular_allow_is_unaffected` | `read_tool` | `SecurityDecision::Allow` |
| `regular_deny_is_unaffected` | `blocked_tool` | `SecurityDecision::Deny` |
| `hitl_taints_not_applied_before_approval` | `test_hitl_tool` with a permit rule that would add a taint | Taint set is unchanged after `HumanApproval` decision |
| `hitl_audit_log_emitted_on_request` | `test_hitl_tool` | Audit log contains `HumanApprovalRequested` entry |

---

### Unit tests: `HookDecision` output format (`tests/hook_hitl_unit.rs`)

Goal: verify `handle_pre_tool` produces the correct `HookDecision` for each scenario.

| Test | Input | Expected |
|---|---|---|
| `hook_ask_json_on_human_approval` | `SecurityDecision::HumanApproval`, mode=interactive | `exit_code=0`, `stdout_json.hookSpecificOutput.permissionDecision == "ask"` |
| `hook_ask_reason_is_approval_prompt` | `SecurityDecision::HumanApproval`, prompt="Foo?" | `permissionDecisionReason == "Foo?"` |
| `hook_defer_json_on_headless` | `HumanApproval`, mode=headless (no TTY) | `exit_code=0`, `permissionDecision == "defer"` |
| `hook_deny_on_unsupported_interface` | `HumanApproval`, adapter=GH_CLI | `exit_code=2`, stderr contains explanation |
| `hook_deny_on_timeout_fallback_closed` | `HumanApproval`, timeout configured | `exit_code=2` after timeout |
| `hook_allow_on_timeout_fallback_open` | `HumanApproval`, `HitlFallback::Allow` configured | `exit_code=0` after timeout |

---

### Integration tests: Claude Code hook (`tests/hook_claude_code_hitl.rs`)

Uses the real binary (via `assert_cmd`). Feeds JSON payloads through stdin, checks stdout JSON and exit code.

| Test | Payload | Expected stdout | Expected exit |
|---|---|---|---|
| `cc_hitl_ask_output_valid_json` | `test_hitl_tool` via hook input | Valid JSON with `hookSpecificOutput` | 0 |
| `cc_hitl_permissionDecision_is_ask` | `test_hitl_tool` | `permissionDecision == "ask"` | 0 |
| `cc_hitl_reason_matches_policy` | `test_hitl_tool` | `permissionDecisionReason == "test_tool requires human approval. Allow?"` | 0 |
| `cc_hitl_allow_tool_gives_allow` | `read_tool` (regular allow) | No `hookSpecificOutput` (or `permissionDecision == "allow"`) | 0 |
| `cc_hitl_deny_tool_gives_deny` | `blocked_tool` (regular deny) | stderr contains reason | 2 |
| `cc_hitl_headless_gives_defer` | `test_hitl_tool`, `LILITH_HITL_MODE=defer` | `permissionDecision == "defer"` | 0 |
| `cc_hitl_policy_file_loads_correctly` | Specify `hitl_policy.cedar` in config | No parse errors, all rules active | — |

---

### Integration tests: MCP elicitation (`tests/mcp_hitl_integration.rs`)

Uses a mock MCP client that implements or withholds the `elicitation` capability. The test drives the full `McpMiddleware` stack.

| Test | Setup | Stimulus | Expected |
|---|---|---|---|
| `mcp_elicitation_sent_on_hitl` | Client declares elicitation capability | `tools/call` for `test_hitl_tool` | `elicitation/create` sent to client |
| `mcp_elicitation_message_matches_policy` | Client declares elicitation | `test_hitl_tool` | `params.message == "test_tool requires human approval. Allow?"` |
| `mcp_elicitation_schema_has_decision_field` | Client declares elicitation | `test_hitl_tool` | `requestedSchema.properties.decision.enum == ["Allow", "Deny"]` |
| `mcp_elicitation_accept_allow_forwards_tool` | Client accepts → Allow | `test_hitl_tool` | Tool forwarded to upstream |
| `mcp_elicitation_accept_deny_blocks_tool` | Client accepts → Deny | `test_hitl_tool` | JSON-RPC error returned, tool NOT forwarded |
| `mcp_elicitation_decline_blocks_tool` | Client declines | `test_hitl_tool` | JSON-RPC error (fail-closed) |
| `mcp_elicitation_cancel_fail_closed` | Client cancels | `test_hitl_tool` | JSON-RPC error (fail-closed default) |
| `mcp_elicitation_cancel_fail_open` | Client cancels, `HitlFallback::Allow` configured | `test_hitl_tool` | Tool forwarded |
| `mcp_no_elicitation_capability_blocks` | Client does NOT declare elicitation | `test_hitl_tool` | JSON-RPC error with message about missing capability |
| `mcp_elicitation_timeout_fail_closed` | Client never responds, `@timeout_secs("1")` | `test_hitl_tool` | JSON-RPC error after ~1s |
| `mcp_elicitation_audit_log_on_request` | Any | `test_hitl_tool` | Audit log contains `HumanApprovalRequested` |
| `mcp_elicitation_audit_log_on_grant` | Accept → Allow | `test_hitl_tool` | Audit log contains `HumanApprovalGranted` |
| `mcp_elicitation_audit_log_on_deny` | Accept → Deny | `test_hitl_tool` | Audit log contains `HumanApprovalDenied` |
| `mcp_regular_allow_no_elicitation` | Any | `read_tool` | No elicitation sent, tool forwarded normally |
| `mcp_regular_deny_no_elicitation` | Any | `blocked_tool` | No elicitation sent, JSON-RPC error returned |
| `mcp_hitl_taint_conditional` | Taint `ACCESS_PRIVATE` present | `search_web` | Elicitation sent |
| `mcp_hitl_taint_not_set_no_elicitation` | No taints | `search_web` | No elicitation, tool forwarded normally |

---

### Integration tests: Agent SDK approval handler (`tests/agent_sdk_hitl.rs`)

Uses `HookHandler::with_approval_handler(...)`. Injects a mock `ApprovalHandler`.

| Test | Handler response | Stimulus | Expected |
|---|---|---|---|
| `sdk_hitl_approval_granted_allows_tool` | Returns `Approved` | `test_hitl_tool` | `handle_with_reason` → `(0, None)` (allow) |
| `sdk_hitl_approval_denied_blocks_tool` | Returns `Denied { reason: "no" }` | `test_hitl_tool` | `(2, Some("no"))` (deny) |
| `sdk_hitl_no_handler_fails_closed` | No handler set | `test_hitl_tool` | `(2, Some("<fail-closed message>"))` |
| `sdk_hitl_timeout_fail_closed` | Handler never returns, `@timeout_secs("1")` | `test_hitl_tool` | `(2, Some("timeout"))` after ~1s |
| `sdk_hitl_timeout_fail_open` | Handler never returns, fail-open configured | `test_hitl_tool` | `(0, None)` after timeout |
| `sdk_hitl_terminal_handler_mock` | `TerminalApprovalHandler` with mocked stdin "y" | `test_hitl_tool` | `(0, None)` |
| `sdk_hitl_terminal_handler_deny_mock` | `TerminalApprovalHandler` with mocked stdin "n" | `test_hitl_tool` | `(2, Some("User denied"))` |
| `sdk_hitl_regular_allow_no_handler_called` | Handler set (verify it is NOT called) | `read_tool` | Handler not invoked, `(0, None)` |

---

### Integration tests: Webhook (Copilot Studio non-support) (`tests/webhook_hitl.rs`)

| Test | Stimulus | Expected response |
|---|---|---|
| `webhook_hitl_policy_returns_1006` | `POST /analyze-tool-execution` with `test_hitl_tool` | `blockAction: true`, `reasonCode: 1006` |
| `webhook_hitl_reason_explains_constraint` | Same | `reason` contains `"Human approval required but Copilot Studio"` |
| `webhook_regular_allow_unaffected` | `read_tool` | `blockAction: false` |
| `webhook_regular_deny_unaffected` | `blocked_tool` | `blockAction: true`, `reasonCode: 1002` |

---

### E2E tests: defer resume flow (`tests/e2e_defer_resume.rs`)

These require the real `lilith-zero` binary and a simulated headless invocation. Marked `#[ignore]` unless `RUN_E2E=1`.

| Test | Scenario |
|---|---|
| `e2e_defer_creates_approval_file` | Hook invoked in headless mode; verify `/tmp/lilith-approval-<session>.json` is created with `pending` status |
| `e2e_defer_resume_with_approval` | Write approval to temp file; invoke hook again; verify allow |
| `e2e_defer_resume_with_denial` | Write denial to temp file; invoke hook again; verify deny + reason |
| `e2e_defer_resume_missing_file_fails_closed` | No temp file; invoke hook; verify deny (fail-closed) |
| `e2e_defer_timeout_fails_closed` | No temp file, `@timeout_secs("2")`; sleep 3s; verify deny |

---

### Cedar policy tests (`tests/cedar_hitl_policy_tests.rs`)

These reuse `hitl_policy.cedar` and verify the annotation extraction logic directly.

| Test | What it verifies |
|---|---|
| `annotation_human_approval_value_is_true` | `get_policy_annotation(id, "human_approval") == Some("true")` |
| `annotation_approval_prompt_extracted` | `get_policy_annotation(id, "approval_prompt")` returns exact string |
| `annotation_reason_extracted` | `get_policy_annotation(id, "reason")` returns exact string |
| `annotation_timeout_secs_extracted` | `get_policy_annotation(id, "timeout_secs")` returns `"10"` |
| `annotation_missing_human_approval_returns_none` | `read_tool` policy has no `@human_approval` → `None` |
| `annotation_human_approval_false_not_triggered` | A policy with `@human_approval("false")` does not produce `HumanApproval` |
| `policy_file_parses_without_error` | `PolicySet::from_str(include_str!("fixtures/hitl_policy.cedar"))` succeeds |

---

## Build sequence

1. Add `Decision::PendingHumanApproval` to `models.rs` — compile check
2. Add `SecurityDecision::HumanApproval` to `events.rs` — compile check
3. Add evaluator branch in `security_core.rs` — write unit tests first, then impl
4. Add `HookDecision` struct, update `handle_pre_tool` — write hook unit tests first, then impl
5. Update `handle_with_reason` and `handle` wrappers in `hook/mod.rs`
6. Add `LilithApprovalRequest`, `LilithApprovalDecision`, `ApprovalHandler` trait, `TerminalApprovalHandler`
7. Implement Claude Code `"ask"` / `"defer"` output in hook main path
8. Implement VS Code adapter (same as Claude Code `"ask"`)
9. Implement MCP elicitation in `mcp/server.rs`
10. Implement Agent SDK `with_approval_handler` on `HookHandler`
11. Implement Copilot Studio webhook `1006` response in `server/webhook.rs`
12. Implement GH CLI graceful deny in its adapter
13. Add `on_human_approval_*` methods to `TelemetryHook`
14. Wire `HitlConfig` into `Config` (env vars: `LILITH_HITL_TIMEOUT_SECS`, `LILITH_HITL_FALLBACK`)
15. Add temp-file-based defer state for E2E tests

---

## Sources

### Online documentation

- [Claude Code hooks reference](https://code.claude.com/docs/en/hooks) — `permissionDecision` values (`ask`, `defer`, `allow`, `deny`), `HookDecision` JSON schema, exit code semantics
- [Claude Code permissions](https://code.claude.com/docs/en/permissions) — **Critical**: hook execution order vs permission rules; "Always allow" creates an allow rule; deny hooks take precedence over allow rules; allow rules bypass `"ask"` from hook
- [Handle approvals — Agent SDK](https://code.claude.com/docs/en/agent-sdk/user-input) — `canUseTool` callback API, `PermissionResultAllow`, `PermissionResultDeny`, `defer` in TypeScript SDK
- [Agent hooks in VS Code](https://code.visualstudio.com/docs/copilot/customization/hooks) — `ask` support, no `defer`, `updatedInput` support
- [Using hooks with GitHub Copilot](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/use-hooks) — no `permissionDecision` documented; exit codes only
- [MCP Elicitation specification (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation) — form mode, URL mode, capability declaration, three-action response model (`accept`/`decline`/`cancel`), timeout handling
- [Copilot Studio threat detection webhook](https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers) — 1-second timeout, `AnalyzeToolExecutionResponse` schema, `reasonCode` field
- [Multistage approvals — Copilot Studio](https://learn.microsoft.com/en-us/microsoft-copilot-studio/flows-advanced-approvals) — Power Automate Human review connector, future Copilot Studio HITL path

### Local documentation

- [`docs/concepts/human-in-the-loop.md`](./human-in-the-loop.md) — per-interface requirements overview, sources, "Always allow" note
- [`examples/copilot_studio/docs/telemetry.md`](../../examples/copilot_studio/docs/telemetry.md) — what Copilot Studio logs; why reasonCode 1006 goes to Sentinel
- [`examples/copilot_studio/docs/sentinel-integration-spec.md`](../../examples/copilot_studio/docs/sentinel-integration-spec.md) — ASIM schema, `on_human_approval_*` telemetry hooks feed into this
- [`lilith-zero/tests/fixtures/`](../../lilith-zero/tests/fixtures/) — existing fixture directory; `hitl_policy.cedar` goes here
