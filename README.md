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
| **Session Integrity** | HMAC-SHA256 session binding, constant-time validation |
| **Logic Engine** | Multi-stage Policy Evaluator (Static + Taint + Resource) |
| **Taint Tracking** | Compile-time `Tainted<T>` enforcement (Rust) + Runtime Sink blocking |
| **Spotlighting** | Per-response randomized delimiters (Prompt Injection defense) |
| **Process Binding** | OS Job Objects (Win) / `PDEATHSIG` (Linux) process supervision |
| **Actor Model** | Fully async internal messaging (Tokio) - Deadlock-free I/O |

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
id: sentinel-policy
customerId: demo-user
name: Hardened Enterprise Policy
version: 1

staticRules:
  query_db: ALLOW
  execute_shell: DENY

taintRules:
  - tool: get_user_profile
    action: ADD_TAINT
    tag: PII
    
  - tool: send_email
    action: CHECK_TAINT
    forbiddenTags: [PII]
    error: "Policy violation: PII exfiltration blocked."

resourceRules:
  - uriPattern: "file:///config/*"
    action: BLOCK
```

## Architecture

"Permanent Sentinel" Architecture:

```
Agent ◄──LSP-RPC (stdio)──► [Protocol Adapter] ◄──SecurityEvent──► [Security Core]
                                                                        │
                                                                 ┌──────┴──────┐
                                                                 │ Policy      │
                                                                 │ Engine      │
                                                                 └─────────────┘
```

1. **Protocol Adapter**: Decouples wire protocol from core security state. Supports both legacy NDJSON and LSP-style `Content-Length` framing.
2. **Async Actor Core**: Message-passing pipeline (Tokio + Channels) ensures non-blocking I/O across stdin/stdout/stderr.
3. **Type-Driven Security**: Internal `SafeString`/`TaintedString` types enforce compiler-checked security boundaries.

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
# Run verified security suite
python -m unittest tests.test_security_hardening

# Run basic flow sanity check
python -m unittest tests.test_basic_flow
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

- [sentinel/](sentinel/) — Binary (Rust)
- [sentinel_sdk/](sentinel_sdk/) — Client SDK (Python)
- [tests/](tests/) — Test suites & resources
- [examples/](examples/) — Reference implementations

## License

[Apache-2.0](LICENSE)
