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
| **Spotlighting** | Wrap outputs in randomized delimiters to mark untrusted content |
| **Process Binding** | Job Objects (Windows) / PR_SET_PDEATHSIG (Linux) |

## Usage

```python
from sentinel_sdk import Sentinel

client = Sentinel.start(
    upstream="python tools.py",
    policy="policy.yaml"
)

async with client:
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

```
Agent ◄──stdio──► Sentinel ◄──stdio──► Tool Server
                     │
              ┌──────┴──────┐
              │ Policy      │
              │ Engine      │
              └─────────────┘
```

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

## Verification

```bash
python examples/demo.py
```

```
[PASS] HMAC-signed session IDs
[PASS] Static ALLOW policy
[PASS] Static DENY policy
[PASS] Dynamic taint tracking
[PASS] Data exfiltration prevention
[PASS] Spotlighting

TOTAL: 6/6 features verified
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
