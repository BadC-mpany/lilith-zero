# Sentinel Examples

This directory contains reference implementations and demos for the Sentinel middleware.

## 1. React Agent Demo (`react_agent_demo/`)

A comprehensive showcase of Sentinel protecting a ReAct-style agent.

- **`demo.py`**: Properties of Sentinel (Taint Tracking, Fail-Closed, Spotlighting).
- **`agent.py`**: A minimal ReAct agent implementation.
- **`mock_server.py`**: A compliant MCP server for testing without external dependencies.
- **`policy.yaml`**: The security rules enforcing the demo logic.

**Run:**
```bash
python examples/react_agent_demo/demo.py
```

## 2. Simple Demo (`simple_demo/`)

A minimal "Hello World" for Sentinel.

- Shows basic connection and tool listing.
- Good starting point for understanding the SDK `Sentinel` class.

**Run:**
```bash
python examples/simple_demo/main.py
```

## Prerequisites
Ensure the `sentinel_sdk` is installed:
```bash
pip install -e sentinel_sdk
```
