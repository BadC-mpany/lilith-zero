# Lilith Zero Examples

Curated examples of the Lilith Security Middleware in action.

## Directory Structure

### Python Examples (`examples/python/`)

- **`minimal/`**: The minimalist "Hello World". Demonstrates basic connectivity and static policy (Allow/Deny).
- **`fastmcp/`**: Transparent wrapping of any MCP server. Shows Lilith securing a calculator server (static deny + resource ACL) without any framework dependency.
- **`advanced/`**: Comprehensive feature showcase. Demonstrates Taint Tracking, Logic Rules, Resource Control, Spans, and Audit Logs.
- **`langchain/`**: Agentic loop simulation. Demonstrates multi-turn tool use with taint-based exfiltration guard (no framework required).
- **`lovable/`**: Securing Vibe Coding apps (Lovable/Replit).

## Requirements

1. **Python 3.10+**
2. **Lilith Binary**: Built via `cargo build -p lilith-zero` or installed via `pip install lilith-zero`.
3. **Tools**: `uv` is recommended for dependency management.

## Running Examples

We recommend using `uv` to run examples in isolated environments.

```bash
# 1. Minimal Demo
uv run examples/python/minimal/agent.py

# 2. FastMCP / Transparent Wrapping
uv run examples/python/fastmcp/agent.py

# 3. Advanced Features
uv run examples/python/advanced/agent.py

# 4. Agentic Loop
uv run examples/python/langchain/agent.py
```

## Integration Tests

The `tests/` directory contains a full end-to-end test suite that exercises every example against a real Lilith binary.

```bash
# Build the binary first
cargo build --release -p lilith-zero
export LILITH_ZERO_BINARY_PATH="$(pwd)/lilith-zero/target/release/lilith-zero"

# Run all example tests
python -m pytest examples/python/tests -v

# Run a single scenario
python -m pytest examples/python/tests/test_examples.py::test_advanced_taint_sink_blocked -v
```

## Key Concepts

- **Policy Enforcement**: Declarative security rules in `policy.yaml`.
- **Fail-Closed**: Default-deny architecture.
- **Taint Tracking**: Preventing data exfiltration.
- **Process Isolation**: Automatic lifecycle management.
