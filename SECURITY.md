# Security Policy & Architecture

## Security Philosophy

Lilith Zero operates on a **Zero Trust, Defense-in-Depth** architecture designed to withstand adversarial LLM outputs, compromised tools, and hostile runtime environments. We assume that:
1.  **AI Agents are Untrusted:** LLM outputs may contain prompt injection or jailbreak payloads.
2.  **Tools are Vectors:** External tools may be coerced into exfiltrating data.
3.  **Runtime is Hostile:** The execution environment must be rigorously isolated.

Our security engineering process adheres to **rigorous assurance standards**, integrating formal verification, continuous fuzzing, and hermetic red-teaming into every CI pipeline.

## Rigorous Verification Methodology

We employ a multi-layered verification strategy to ensure mathematical correctness and runtime safety.

### 1. Formal Verification (Kani)
We use the **Kani Rust Verifier** to mathematically prove the absence of memory safety errors and logical flaws in critical paths.

| Verified Invariant | Status | Verification Method |
| :--- | :--- | :--- |
| **Taint Sanitization** | **PROVEN** | `prove_taint_clean_logic`: Formally proves that `Taint::into_inner()` preserves data integrity while stripping metadata. |
| **Overflow Safety** | **PROVEN** | `prove_content_length_no_overflow`: Proves `Content-Length` parsing is immune to integer overflow/underflow. |
| **Session Entropy** | **PROVEN** | `prove_session_id_format`: Proves session IDs meet >256-bit entropy and strict format requirements. |

### 2. Static Analysis & Supply Chain
- **Strict Clippy:** `cargo clippy -- -D warnings` enforces strict Rust idioms and safety checks.
- **Dependency Audit:** Continuous scanning via `cargo audit` and `cargo deny` for vulnerabilities and license compliance.
- **Type Safety:** Python SDK enforces rigorous typing via `mypy --strict`.

### 3. Red Team & Fuzzing
- **Hermetic Red Teaming:** Automated `pytest` suite (`sdk/tests/red_team/`) simulates active attacks:
    - Prompt Injection simulation
    - JSON-RPC malformation attacks
    - Policy bypass attempts
- **Fuzzing:** `cargo fuzz` harnesses target the JSON-RPC codec to identify edge-case crashes (executed in Linux CI).

## Security vs. Performance Benchmarks

Security does not come at the cost of latency. Our Rust-based core is optimized for microsecond-scale overhead.

**Benchmark Results (Intel High-Performance Tier):**

| Component | Operation | Mean Latency | Throughput Est. |
| :--- | :--- | :--- | :--- |
| **MCP Codec** | `decode_ping` | **~247 ns** | ~4M msgs/sec |
| **Policy Engine** | `validate_policy` | **~660 ns** | ~1.5M validations/sec |

*Benchmarks generated via Criterion.rs on production-grade optimization profiles.*

## Reporting a Vulnerability

We take security reports seriously and adhere to a coordinated disclosure policy.

### **DO NOT create a public GitHub issue.**

**Contact:** [security@badcompany.xyz](mailto:security@badcompany.xyz) or use GitHub Security Advisories.

**In Scope:**
- Sandbox Escapes (Windows Job Objects, Linux Landlock)
- Policy Evasion / Taint Tracking Bypass
- Cryptographic Weaknesses (Session ID predictability, etc.)
- Remote Code Execution (RCE) via MCP

**Out of Scope:**
- Social Engineering / Phishing
- DoS via resource exhaustion (unless trivially exploitable)
- Attacks requiring physical device access

## Deployment Hardening Checklist

When deploying Lilith Zero in production:

- [ ] **Principle of Least Privilege:** Run the core binary as a restricted user.
- [ ] **Audit Logs:** Enable `RUST_LOG=info` and ship logs to a secure SIEM.
- [ ] **Policy Review:** Audit `ALLOW` rules; prefer `BLOCK` by default.
- [ ] **Update Frequency:** Automate `cargo audit` in your downstream CI.
