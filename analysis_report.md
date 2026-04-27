# Lilith-Zero Comprehensive Security & Architecture Audit

**Date:** April 27, 2026
**Target:** `lilith-zero` (Userspace Process Supervisor & Security Middleware for MCP)

---

## 1. Threat Model & System Constraints

### 1.1 Trust Boundaries
*   **The Agent (Upstream):** UNTRUSTED. LLMs are susceptible to prompt injection, jailbreaks, and hallucinations. All input from the agent is considered `Tainted<T>`.
*   **The Tool Servers (Downstream):** SEMI-TRUSTED. They execute on the host machine but might have vulnerabilities or be hijacked by malicious payloads passed through the agent.
*   **Lilith-Zero Middleware:** TRUST ROOT. Must perfectly enforce the policy boundary, sanitize taints, and isolate the upstream from the downstream.

### 1.2 Threat Actors
1.  **Malicious Prompt / LLM (External Attacker):** Attempts to manipulate the agent into executing arbitrary commands, reading sensitive files (path traversal), or exfiltrating data (lethal trifecta).
2.  **Compromised Tool Server (Internal Attacker):** A vulnerability in an MCP tool (e.g., Python command injection) is exploited to pivot into the host or bypass the middleware's audit logs.

### 1.3 Constraints
*   **Userspace Only:** No eBPF or kernel modules. Relies on OS-level process management (Job Objects, `PR_SET_PDEATHSIG`, kqueue).
*   **Performance:** Sub-millisecond latency overhead. Must not bottleneck the agent's token generation or tool execution.
*   **Fail-Closed:** Any error in parsing, policy evaluation, or process supervision must result in a DENY decision and process termination.
*   **Hexagon Architecture:** The core must remain small and mathematically provable, with adapters (SDKs) handling framework-specific logic.

---

## 2. Identified Vulnerabilities & Bad Patterns

### 2.1 CRITICAL: Path Canonicalization & TOCTOU Bypass
**Location:** `lilith-zero/src/engine_core/path_utils.rs`

1.  **Key-Value Bypass:** `extract_strings` recursively searches JSON for strings but **ignores object keys**. If an attacker tricks a tool into accepting a path as a JSON key (e.g., `{"/etc/shadow": "content"}`), it completely bypasses the `extract_and_canonicalize_paths` check.
2.  **TOCTOU Path Confusion:** The `lexical_canonicalize` function strips leading `../` from relative paths (e.g., `../../../etc/passwd` becomes `etc/passwd`). The Cedar policy engine evaluates the canonicalized string (`etc/passwd`), which might be allowed by a policy. However, the *original, un-canonicalized* JSON is passed to the tool server. The tool server executes using `../../../etc/passwd`, resulting in a successful path traversal attack. 

**Recommendation:** 
*   Update `extract_strings` to inspect object keys.
*   **Enforce strict mutation:** If the middleware modifies or canonicalizes a path for security evaluation, it MUST mutate the JSON payload sent to the tool server to use the exact canonicalized path evaluated by the engine. Never evaluate one string and pass another.

### 2.2 Process Orphan Vulnerabilities (Daemonization Escapes)
**Location:** `lilith-zero/src/mcp/process.rs` & `supervisor.rs`

*   **Linux `PR_SET_PDEATHSIG` Limitation:** If a child process executes a `setuid` or `setgid` binary, the kernel clears the death signal. The child will outlive the supervisor.
*   **Double-Fork Daemonization:** `child.wait()` in `process.rs` only waits for the immediate child. If the MCP tool double-forks and daemonizes, the immediate child exits, the supervisor drops, but the malicious daemon continues running on the host.
*   **macOS Re-Exec Race:** The kqueue supervisor relies on re-executing `self_exe`. If the binary is replaced/deleted during runtime, spawning the supervisor fails.

**Recommendation:** 
*   On Linux/macOS, spawn children in a new **Process Group (setsid/setpgid)**. When killing the child, send `SIGKILL` to the entire process group (`kill -9 -PGID`) to ensure daemonized children are also terminated. 

### 2.3 Authentication Redundancy & Expansion
**Location:** `lilith-zero/src/engine_core/auth.rs`

*   Contains duplicated logic (`if !found { return Err(...) }`).
*   Hardcoded `Algorithm::HS256`. While secure against `alg: none`, it lacks the flexibility needed for enterprise deployments (e.g., RS256 for JWKS / Entra ID).

### 2.4 Incomplete "Lethal Trifecta" Protection
*   The `protect_lethal_trifecta` heuristic currently relies on exact tool classifications. If the `classify_tool` logic fails to correctly map a custom tool to `EXFILTRATION` or `NETWORK`, the fail-safe is bypassed.

---

## 3. Architectural Evolution (Cedar & MCP 2025.11)

### 3.1 Migration to Formally Verifiable Cedar
*   **Current State:** `cedar_evaluator` is wrapped in an `Option`. This creates a split-brain architecture where policies might silently fail to load, resulting in fallback behaviors.
*   **Target State:** Make Cedar the *exclusive* policy engine. Remove the old YAML AST evaluator. Cedar's formal verification guarantees that policy decisions are mathematically sound. 
*   **Implementation:** Map MCP concepts directly to Cedar entities:
    *   `Principal` = `Agent` (with attributes like `SessionId`, `Taints`)
    *   `Action` = `ToolCall` (with attributes mapped from `classify_tool`)
    *   `Resource` = `Host` or `Path`

### 3.2 2025.11 MCP Protocol Support out-of-the-box
The 2025.11 spec introduces tighter lifecycle management and capabilities negotiation.
*   **Hexagon Adherence:** The protocol parser (`protocol/`) should be entirely decoupled from the security core. The codec must parse 2025.11 JSON-RPC frames and convert them into standard `SecurityEvent` structs.
*   **Zero-Heuristic Classification:** Do not rely on `read_` or `write_` string prefixes. Force tool servers to register their security classes in the MCP `tools/list` capabilities metadata, or require the user to explicitly map them in the Cedar policy.

---

## 4. Secure Human-in-the-Loop (HITL) Integration

To create a highly integrable, secure HITL setup without compromising the automated nature of the middleware:

1.  **Asynchronous HITL Taint:** Introduce a `REQUIRES_APPROVAL` taint for high-risk tool classes (e.g., `StateModifying`, `Network`).
2.  **Protocol Extension:** When the Cedar engine evaluates an action that requires approval, instead of a hard `Deny`, the middleware intercepts the call and returns an out-of-band MCP `authorization_request` to the client/IDE (e.g., VS Code or OpenClaw).
3.  **Cryptographic Signatures:** The human approval must be signed. The IDE sends back an `authorization_response` containing a short-lived, HMAC-signed token specifically authorizing that exact tool execution payload.
4.  **Resumption:** The middleware validates the HMAC, strips the `REQUIRES_APPROVAL` taint for that specific execution context, and forwards the JSON to the child process.

### Conclusion for OpenClaw / Copilot / Claude Code
By relying on standard stdio interception (Hexagon model) and cryptographically signed HITL tokens, Lilith-Zero can be installed via a single command (e.g., a simple bash wrapper script that swaps the agent's standard tool binary path with the `lilith-zero` executable). No complex framework integrations are needed; if the agent speaks MCP over stdio, Lilith secures it instantly.