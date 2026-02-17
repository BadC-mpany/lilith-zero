# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in Lilith Zero, please report it responsibly.

**Email**: [peter.tallosy@badcompany.dev](mailto:peter.tallosy@badcompany.dev)

Please include:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment

We aim to respond within 48 hours and publish a fix within 7 days of confirmation.

## Threat Model

Lilith Zero operates under three core assumptions:

1. **Agents are Untrusted**: The LLM-driven agent may be manipulated via prompt injection.
2. **Tools are Vectors**: External tools may be coerced into exfiltrating data.
3. **Runtime is Hostile**: The execution environment must be rigorously isolated.

## Verification Methodology

Our security engineering process integrates formal verification, continuous fuzzing, and hermetic red-teaming into every CI pipeline.

| Assurance Layer | Method | Status |
|:---|:---|:---|
| **Formal Verification** | Kani model checking (bounded proofs) | PASS All harnesses pass |
| **Unit Tests** | Rust `cargo test` + Python `pytest` | PASS Full coverage |
| **Red Team Suite** | Automated attack simulation against policies | PASS All vectors blocked |
| **Static Analysis** | `cargo clippy`, `cargo audit` | PASS Zero warnings |

## Supported Versions

| Version | Supported |
|:---|:---|
| 0.1.x | Active |
