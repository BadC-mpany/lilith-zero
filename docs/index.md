# Lilith Zero

**The Secure Middleware for Model Context Protocol (MCP)**

<div align="center">
  <p>
    <em>Bringing rigorous process isolation and security policy enforcement to AI Agent workflows.</em>
  </p>
</div>

---

## What is Lilith Zero?

**Lilith Zero** is a security middleware designed for the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). It acts as a secure proxy between your AI Agent (like Claude, ChatGPT, or LangChain) and the tools it uses.

By intercepting all communication, Lilith Zero enforces:

1.  **Process Isolation**: Every tool runs in a strictly isolated environment (Windows Job Objects, macOS Re-Exec Supervisor, Linux Namespaces).
2.  **Lethal Trifecta Protection**: Prevents the dangerous combination of *Private Data Access* + *Untrusted Computation* + *Exfiltration*.
3.  **Policy Enforcement**: Granular control over what tools can be called and with what arguments.

## Key Features

<div class="grid cards" markdown>

-   :material-shield-lock: **Fail-Closed Security**
    ---
    Default-deny architecture ensures that no tool runs without explicit permission.

-   :material-eye: **Deep Observability**
    ---
    Full audit logs of every tool execution, argument, and output.

-   :material-server-network: **Process Supervision**
    ---
    Automatic cleanup of zombie processes and resource limits enforcement.

-   :material-file-document-edit: **Declarative Policies**
    ---
    Define security rules in simple YAML files.

</div>

## Quick Start

Install Lilith Zero via cargo:

```bash
cargo install lilith-zero
```

[Get Started](getting-started/index.md){ .md-button .md-button--primary }
[Read the Docs](concepts/architecture.md){ .md-button }
