# Lilith Zero

**Security Middleware for Agents and MCP Servers**

*Process isolation, policy enforcement, and verified security for AI agent tool execution.*

---

[![GitHub release](https://img.shields.io/github/v/release/BadC-mpany/lilith-zero?style=flat-square)](https://github.com/BadC-mpany/lilith-zero/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](https://github.com/BadC-mpany/lilith-zero/blob/main/LICENSE)
[![PyPI](https://img.shields.io/pypi/v/lilith-zero?style=flat-square)](https://pypi.org/project/lilith-zero/)

## Quick Install

```bash title="Terminal"
pip install lilith-zero
```

Or with `uv`:

```bash title="Terminal"
uv add lilith-zero
```

Or build the Rust core from source:

```bash title="Terminal"
cargo install --path lilith-zero
```

## What is Lilith Zero?

**Lilith Zero** is a security middleware for the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). It acts as a secure proxy between your AI Agent (Claude, ChatGPT, LangChain) and the tools it uses.

By intercepting all communication, Lilith Zero enforces:

1.  **Process Supervision**: Every tool runs with strict lifecycle controls (Windows Job Objects, macOS Re-Exec Supervisor, Linux `PR_SET_PDEATHSIG`).
2.  **Lethal Trifecta Protection**: Prevents the dangerous combination of *Private Data Access* + *Untrusted Computation* + *Exfiltration*.
3.  **Policy Enforcement**: Granular control over what tools can be called and with what arguments.

## Key Features

- :material-shield-lock:{ .lg } **Fail-Closed Security** — Default-deny architecture ensures that no tool runs without explicit permission.

- :material-eye:{ .lg } **Deep Observability** — Full audit logs of every tool execution, argument, and output.

- :material-server-network:{ .lg } **Process Supervision** — Automatic cleanup of zombie processes and resource limits enforcement.

- :material-file-document-edit:{ .lg } **Declarative Policies** — Define security rules in simple YAML with logical conditions (`and`, `or`, `not`).

- :material-check-decagram:{ .lg } **Verified Security** — Critical security invariants proven correct via Kani model checking.

- :material-bug:{ .lg } **Red Team Suite** — Automated attack simulations to validate your policies.

## Next Steps

[Get Started](getting-started/installation.md){ .md-button .md-button--primary }
[Core Concepts](concepts/architecture.md){ .md-button }
[See Examples](guides/secure-agent-integration.md){ .md-button }