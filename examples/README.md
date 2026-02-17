# Lilith Zero Examples

Curated examples of the Lilith Security Middleware in action.

## Directory Structure

### Python Examples (`examples/python/`)

- **`minimal/`**: The minimalist "Hello World". Demonstrates basic connectivity and static policy (Allow/Deny).
- **`langchain/`**: Framework integration. Demonstrates wrapping LangChain tools with Lilith security.
- **`fastmcp/`**: Modern MCP integration. Shows how to secure `FastMCP` servers.
- **`advanced/`**: Comprehensive feature showcase. Demonstrates Taint Tracking, Logic Rules, and Resource Control.
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

# 2. LangChain Integration
uv run examples/python/langchain/agent.py

# 3. FastMCP Integration
uv run examples/python/fastmcp/agent.py

# 4. Advanced Features
uv run examples/python/advanced/agent.py
```

## Key Concepts

- **Policy Enforcement**: Declarative security rules in `policy.yaml`.
- **Fail-Closed**: Default-deny architecture.
- **Taint Tracking**: Preventing data exfiltration.
- **Process Isolation**: Automatic lifecycle management.
