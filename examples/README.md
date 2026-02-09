# Lilith Examples

This directory contains reference implementations and demos for the Lilith middleware.

## 1. React Agent Demo (`react_agent_demo/`)

A comprehensive showcase of Lilith protecting a ReAct-style agent.

- **`demo.py`**: Properties of Lilith (Taint Tracking, Fail-Closed, Spotlighting).
- **`agent.py`**: A minimal ReAct agent implementation.
- **`mock_server.py`**: A compliant MCP server for testing without external dependencies.
- **`policy.yaml`**: The security rules enforcing the demo logic.

**Run:**
```bash
python examples/react_agent_demo/demo.py
```

## 2. Simple Demo (`simple_demo/`)

A minimal "Hello World" for Lilith.

- Shows basic connection and tool listing.
- Good starting point for understanding the SDK `Lilith` class.

**Run:**
```bash
python examples/simple_demo/agent.py
```

## 3. LangChain Agent (`langchain_agent/`)

A sophisticated ReAct agent demonstration using LangChain.

- **`agent.py`**: Minimalist LangChain agent integrated with `lilith_zero`.
- **`policy.yaml`**: Full suite of v0.1.0 security policies (ACL, Taint, Logic).
- **`upstream.py`**: Binary-safe MCP server implementation.

**Run:**
```bash
uv run python examples/langchain_agent/agent.py
```

## Prerequisites
Ensure the `lilith_zero` is installed:
```bash
pip install -e sdk/
```
