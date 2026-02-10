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
Lilith Zero enforces **Filesystem isolation**. Tools run in a sandbox that only sees a temporary workspace or strictly allowlisted directories. They **cannot** read `~/.ssh/id_rsa` or `.env` files unless you explicitly allow it.

### 2. Breaking "Untrusted Computation"
We assume the LLM *will* try to run malicious code.
-   **Input Validation**: Strict schema validation for tool arguments.
-   **Execution Limits**: Tools have timeouts and memory limits.
-   **Sandboxing**: Even if the tool is malicious, it runs in a Restricted Token context (Windows) or a restricted namespace (Linux), limiting the blast radius.

### 3. Breaking "Exfiltration"
Lilith Zero acts as a network firewall for the Agent.
-   **Network Block by Default**: Sandboxed processes have **NO** network access by default.
-   **Audit Logging**: Every byte sent to `stdout` is logged. If data leaks, you have a forensic trail.

## Fail-Closed Design

Lilith Zero follows a **Fail-Closed** philosophy.

-   If the policy file is missing -> **Deny All**.
-   If the policy file is malformed -> **Crash Safely (Panic)**.
-   If the audit log cannot be written -> **Stop Execution**.

This ensures that the system never degrades into an insecure state.
