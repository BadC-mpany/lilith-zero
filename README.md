# Sentinel

Deterministic security enforcement for MCP tool calls.

[![CI](https://github.com/peti12352/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/peti12352/sentinel/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Problem

LLM agents with tool access are vulnerable by design:

- **Prompt injection** hijacks agent behavior via untrusted data
- **Session hijacking** exploits predictable identifiers  
- **Data exfiltration** leaks sensitive information to external services
- **Zombie processes** persist after agent crashes

Existing solutions rely on probabilistic defenses (prompt engineering) or require rewriting tools. Sentinel provides deterministic policy enforcement without modifying upstream code.

## Solution

Sentinel intercepts MCP traffic via stdio, applying:

| Defense | Mechanism |
|---------|-----------|
| **Session Integrity** | HMAC-SHA256 signed session IDs, constant-time validation |
| **Policy Enforcement** | Static ALLOW/DENY rules per tool |
| **Taint Tracking** | Block sinks (email, APIs) after accessing sources (PII, databases) |
| **Spotlighting** | Randomized delimiters prevent tool-output prompt injection. |
| **Observability** | Structured JSON audit logs and OTEL instrumentation. |
| **Process Binding** | Job Objects (Windows) / PR_SET_PDEATHSIG (Linux) + Explicit Drop Cleanup |
| **Protocol Agnostic** | Auto-negotiates MCP version (2024/2025) via Adapters |

## Usage

```python
from sentinel_sdk import Sentinel

# 1. Start Sentinel Middleware
client = Sentinel.start(
    upstream_cmd="python tools.py",
    policy_path="policy.yaml"
)

# 2. Use as standard MCP client
async with client:
    # List tools (Sentinel enforces "tools/list" policies)
    tools = await client.get_tools_config()
    
    # Execute tool (Sentinel enforces "tools/call" policies & taints)
    result = await client.execute_tool("query_db", {"sql": "SELECT * FROM users"})
```

## Policy Example

```yaml
static_rules:
  query_db: ALLOW
  execute_shell: DENY

taint_rules:
  - tool: get_user_profile
    action: ADD_TAINT
    taint_tags: [PII]
    
  - tool: send_email
    action: CHECK_TAINT
    forbidden_taints: [PII]
    message: "Cannot email after accessing PII"
```

## Architecture

"Permanent Sentinel" Architecture:

```
Agent ◄──JSON-RPC (stdio)──► [Protocol Adapter] ◄──SecurityEvent──► [Security Core]
                                                                        │
                                                                 ┌──────┴──────┐
                                                                 │ Policy      │
                                                                 │ Engine      │
                                                                 └─────────────┘
```

1. **Protocol Adapter**: Decouples wire format from security logic. Auto-detects MCP 2024 or 2025.
2. **Security Core**: Pure logic kernel. Enforces policies, tracks taints, and validates sessions.
3. **Hardened Design**: Fail-closed defaults, constant-time crypto, and strict session binding.

Sentinel runs as a transparent proxy. No agent or tool modifications required.

## Requirements

- Python 3.10+
- Rust 1.70+ (build only)

## Installation

```bash
# Build interceptor
cd sentinel && cargo build --release

# Install SDK
pip install -e sentinel_sdk

# Set binary path
export SENTINEL_BINARY_PATH="./sentinel/target/release/sentinel"
```

## Configuration

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `SENTINEL_MCP_VERSION` | Protocol version (`2024-11-05` or `2025-06-18`) | `2024-11-05` (Auto-negotiates) |
| `SENTINEL_SECURITY_LEVEL` | Security strictness (`audit_only`, `medium`, `high`) | `medium` |
| `POLICIES_YAML_PATH` | Path to policy file | None |
| `SENTINEL_OWNER` | Owner ID for audit logs | `unknown` |

## Verification


```bash
# Run the End-to-End Attack/Defense Demo
python examples/secure_agent_demo.py

# Run the Comprehensive Hardening Test Suite
python examples/hardening_test_suite.py
```

Expected Output (Hardening Suite):
```text
TEST: Fail Closed (No Policy) ... Verified Block
TEST: Static Policy Allow ... Verified Allow
TEST: Taint Propagation & Blocking ... Verified Taint Block
TEST: Spotlighting Integrity ... Verified Spotlighting
OK
```

## Comparison

| | Sentinel | Prompt Engineering | Agent Frameworks |
|-|----------|-------------------|------------------|
| **Enforcement** | Deterministic | Probabilistic | Varies |
| **Session Security** | HMAC-signed | None | API keys |
| **Taint Tracking** | Cross-tool | N/A | N/A |
| **Process Isolation** | OS-level | None | None |
| **Tool Modifications** | None | None | Required |

## Documentation

- [sentinel/](sentinel/) — Rust interceptor
- [sentinel_sdk/](sentinel_sdk/) — Python SDK
- [examples/](examples/) — Demo scripts and policies
- [SECURITY.md](SECURITY.md) — Vulnerability disclosure

## License

[Apache-2.0](LICENSE)
