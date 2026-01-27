# Sentinel

**Zero-Trust Security Middleware for AI Agent Tool Execution**

Sentinel is a security layer that intercepts and enforces policies on MCP (Model Context Protocol) tool calls. It protects against prompt injection, data exfiltration, and unauthorized tool access by applying deterministic security rules to every tool invocation.

## Key Features

- **Session Integrity** - HMAC-signed session IDs with constant-time validation
- **Static Policy Enforcement** - ALLOW/DENY rules per tool
- **Dynamic Taint Tracking** - Block data exfiltration based on information flow
- **Spotlighting** - Wrap tool outputs in delimiters to defend against prompt injection
- **Process Isolation** - Windows Job Objects / Linux PR_SET_PDEATHSIG for child process binding

## Architecture

```
┌─────────────┐     stdio      ┌──────────────────┐     stdio      ┌─────────────┐
│   LLM/Agent │ ◄────────────► │  Sentinel        │ ◄────────────► │  MCP Tool   │
│   (SDK)     │   JSON-RPC     │  Interceptor     │   JSON-RPC     │  Server     │
└─────────────┘                │  (Rust)          │                └─────────────┘
                               │                  │
                               │  ┌────────────┐  │
                               │  │ Policy     │  │
                               │  │ Engine     │  │
                               │  └────────────┘  │
                               └──────────────────┘
```

Sentinel acts as a transparent MCP proxy. The SDK spawns the Rust interceptor, which in turn spawns the upstream tool server. All communication flows through Sentinel, enabling policy enforcement without modifying existing tools.

## Quick Start

### Prerequisites

- Python 3.10+
- Rust 1.70+ (for building the interceptor)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/sentinel.git
cd sentinel

# Build the Rust interceptor
cd sentinel_middleware
cargo build --release
cd ..

# Install the Python SDK
pip install -e sentinel_sdk
```

### Basic Usage

```python
import asyncio
from sentinel_sdk import Sentinel

async def main():
    # Start a Sentinel-protected session
    client = Sentinel.start(
        upstream="python my_tools.py",   # Your MCP tool server
        policy="policy.yaml",             # Security policy file
        security_level="high"             # low | medium | high
    )
    
    async with client:
        # Execute tools through Sentinel
        result = await client.execute_tool("get_weather", {"city": "London"})
        print(result)

asyncio.run(main())
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SENTINEL_BINARY_PATH` | Path to sentinel-interceptor binary |
| `POLICIES_YAML_PATH` | Default policy file path |
| `LOG_LEVEL` | Logging level (trace, debug, info, warn, error) |

## Policy Configuration

Policies are defined in YAML format:

```yaml
id: enterprise-policy
name: Enterprise Security Policy
version: 1

# Static rules: tool-level ALLOW/DENY
static_rules:
  get_weather: ALLOW
  read_database: ALLOW
  send_email: ALLOW
  execute_shell: DENY
  delete_records: DENY

# Dynamic taint rules: track data flow
taint_rules:
  # Mark tools as data sources
  - tool: get_user_profile
    action: ADD_TAINT
    taint_tags: [PII]
  
  - tool: read_database
    action: ADD_TAINT
    taint_tags: [INTERNAL_DATA]
  
  # Block sinks when tainted
  - tool: send_email
    action: CHECK_TAINT
    forbidden_taints: [PII]
    message: "Cannot send email after accessing PII data"
  
  - tool: post_to_slack
    action: CHECK_TAINT
    forbidden_taints: [PII, INTERNAL_DATA]
    message: "Cannot post to Slack after accessing sensitive data"
```

## Security Features

### 1. Session Integrity

Every session gets a cryptographically signed session ID:
```
Format: {version}.{uuid_base64}.{hmac_signature_base64}
Example: 1.JZ_nK24NR2mDB5TgH0wFtA.eA3m3n9EPTpvMhxIm_1rXj5iwLKylTZ28XUF652Ud9Q
```

The SDK automatically injects session IDs into requests. The interceptor validates signatures using constant-time comparison to prevent timing attacks.

### 2. Spotlighting

All tool outputs are wrapped in randomized delimiters:
```
<<<SENTINEL_DATA_START:BqZGoup0>>>
{actual tool output}
<<<SENTINEL_DATA_END:BqZGoup0>>>
```

This helps LLMs distinguish between trusted instructions and external data, defending against prompt injection attacks.

### 3. Taint Tracking

Sentinel tracks which "sensitive" tools have been called in a session:
1. **Source tools** (e.g., `get_user_profile`) add taint tags
2. **Sink tools** (e.g., `send_email`) check for forbidden taints
3. If a sink is called after a forbidden source, the call is blocked

This prevents data exfiltration patterns like: read PII → send to external service.

### 4. Process Isolation

Child processes are bound to the parent's lifecycle:
- **Windows**: Job Objects with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
- **Linux**: `PR_SET_PDEATHSIG` with `SIGKILL`

If Sentinel crashes or is terminated, all child processes are automatically killed.

## SDK Reference

### Sentinel.start()

```python
client = Sentinel.start(
    upstream: str,           # Command to run tool server
    policy: str = None,      # Path to policy YAML
    security_level: str = "high",  # low | medium | high
    binary_path: str = None  # Explicit path to interceptor
)
```

### SentinelClient Methods

```python
# Execute a tool
result = await client.execute_tool(tool_name: str, args: dict)

# List available tools
tools = await client.get_tools_config()

# Get LangChain-compatible tools
lc_tools = await client.get_langchain_tools()
```

### System Prompts

When using Spotlighting, add this to your LLM system prompt:

```python
from sentinel_sdk import Sentinel

system_prompt = Sentinel.get_system_prompt()
# Returns guidance about SENTINEL delimiters
```

## Project Structure

```
sentinel/
├── sentinel_middleware/     # Rust interceptor
│   ├── src/
│   │   ├── main.rs          # CLI entry point
│   │   ├── constants.rs     # Centralized constants
│   │   ├── mcp/
│   │   │   ├── server.rs    # MCP middleware logic
│   │   │   ├── transport.rs # JSON-RPC over stdio
│   │   │   ├── process.rs   # Process supervision
│   │   │   └── security.rs  # Spotlighting
│   │   ├── engine/
│   │   │   └── evaluator.rs # Policy evaluation
│   │   └── core/
│   │       ├── crypto.rs    # HMAC session signing
│   │       ├── models.rs    # Domain types
│   │       └── errors.rs    # Error types
│   └── Cargo.toml
├── sentinel_sdk/            # Python SDK
│   ├── src/
│   │   ├── sentinel_sdk.py  # Client implementation
│   │   ├── constants.py     # SDK constants
│   │   └── prompts.py       # LLM system prompts
│   ├── __init__.py          # Public API
│   └── pyproject.toml
├── examples/
│   ├── demo.py              # Full feature demonstration
│   ├── mock_tools.py        # Example MCP tool server
│   └── enterprise_policy.yaml
└── tests/
    └── test_integration.py
```

## Running the Demo

```bash
# Set binary path
export SENTINEL_BINARY_PATH="./sentinel_middleware/target/release/sentinel-interceptor"

# Run demo
python examples/demo.py
```

Expected output:
```
[PASS] HMAC-signed session IDs
[PASS] Static ALLOW policy
[PASS] Static DENY policy
[PASS] Dynamic taint tracking
[PASS] Data exfiltration prevention
[PASS] Spotlighting (prompt injection defense)

TOTAL: 6/6 features verified
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

For vulnerability reports, see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the Apache License 2.0 - see [LICENSE](LICENSE) for details.
