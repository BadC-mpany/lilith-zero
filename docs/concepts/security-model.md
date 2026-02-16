# Security Model: The Lethal Trifecta

The core design philosophy of Lilith Zero is built around mitigating the **Lethal Trifecta** of AI Agent risks.

## The Lethal Trifecta

Classic security models focus on "Malicious Users" attacking "Trusted Servers." In the Age of Agents, the threat model is inverted: **Trusted Users** are employing **Untrusted Agents** that have high-level capabilities.

The "Lethal Trifecta" occurs when an Agent has:

1.  **Private Data Access**: Ability to read sensitive files (API keys, customer DBs, emails).
2.  **Untrusted Computation**: Ability to execute arbitrary code (Python interpreter, Shell scripts).
3.  **Exfiltration Capability**: Ability to send data to the outside world (Internet access, cURL).

!!! danger "The Risk"
    If an Agent possesses all three capabilities, it can be tricked (via Prompt Injection) into:
    1. **Reading** your API keys (Private Data).
    2. **Processing** them (Computation).
    3. **Sending** them to an attacker (Exfiltration).

## How Lilith Zero Mitigates It

Lilith Zero breaks the trifecta by enforcing strict **separation of concerns** and **principle of least privilege**.

### 1. Breaking "Private Data Access"
Lilith Zero enforces **Policy-based Access Control**. Tools are inspected before execution. If an agent tries to call `read_file` on `~/.ssh/id_rsa`, the Policy Engine:
1.  Intercepts the call.
2.  Matches the arguments against allowlisted Regex patterns.
3.  **Blocks** the request if it violates the policy.

### 2. Breaking "Untrusted Computation"
We assume the LLM *will* try to run malicious code.
-   **Input Validation**: Strict schema validation for tool arguments.
-   **Execution Limits**: Tools are child processes with strict lifecycle management.
-   **Dependencies**: Tools run in hermetic environments (via `uv`) where possible.

### 3. Breaking "Exfiltration"
Lilith Zero acts as a sentinel for Tool capabilities.
-   **Capability Restriction**: You can define a policy that strictly **DENIES** any tool capable of network access (e.g., `curl`, `requests`).
-   **Audit Logging**: Every tool execution and its result is logged.

## Fail-Closed Design

Lilith Zero follows a **Fail-Closed** philosophy.

-   If the policy file is missing -> **Deny All**.
-   If the policy file is malformed -> **Crash Safely (Panic)**.
-   If the audit log cannot be written -> **Stop Execution**.

This ensures that the system never degrades into an insecure state.
