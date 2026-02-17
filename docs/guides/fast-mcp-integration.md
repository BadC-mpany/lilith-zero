# FastMCP Integration

This guide demonstrates how to secure **FastMCP** servers with Lilith Zero.

## Overview

[FastMCP](https://github.com/jlowin/fastmcp) is a modern, high-level Python library for building MCP servers. Lilith Zero wraps these servers to add policy enforcement, process isolation, and audit logging without changing a single line of server code.

## 1. The FastMCP Server

Create a standard FastMCP server (`server.py`).

```python
from fastmcp import FastMCP

mcp = FastMCP("DemoServer")

@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers"""
    return a + b

if __name__ == "__main__":
    mcp.run()
```

## 2. The Lilith Wrapper

In your client application (e.g., an Agent), wrap the execution command with `Lilith`.

```python
import asyncio
from lilith_zero import Lilith

async def main():
    async with Lilith(
        # Lilith launches the FastMCP server as a subprocess
        upstream="uv run fastmcp run server.py", 
        policy="policy.yaml"
    ) as client:
        
        # Tools are now protected by Lilith's policy engine
        result = await client.call_tool("add", {"a": 10, "b": 20})
        print(result)

if __name__ == "__main__":
    asyncio.run(main())
```

## 3. The Policy

Define your security rules in `policy.yaml`.

```yaml
staticRules:
  add: "ALLOW"
  delete_db: "DENY"

protectLethalTrifecta: true
```

## 4. Run It

```bash
uv run agent.py
```

Lilith automatically handles the stdio communication, enforcing the policy on every request before it reaches the FastMCP server.
