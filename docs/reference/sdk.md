# Python SDK Reference

## Overview

The `lilith-zero` Python SDK provides an async client for communicating with MCP tool servers through the Lilith Zero security middleware. Install it via:

```bash
pip install lilith-zero
```

---

## Module: `lilith_zero`

::: lilith_zero
    options:
      show_root_heading: false
      show_source: false
      members: false

---

## Class: `Lilith`

The primary client class. Manages the lifecycle of the middleware process and provides methods for interacting with MCP tools.

::: lilith_zero.client.Lilith
    options:
      show_source: false
      heading_level: 3

### Usage

```python
import asyncio
from lilith_zero import Lilith
from lilith_zero.exceptions import PolicyViolationError

async def main():
    async with Lilith(
        upstream="python server.py",
        policy="policy.yaml"
    ) as client:
        tools = await client.list_tools()
        result = await client.call_tool("ping", {})

asyncio.run(main())
```

---

## Module: `lilith_zero.exceptions`

::: lilith_zero.exceptions
    options:
      show_source: false
      heading_level: 3

---

## Constants

| Name | Value | Description |
|:---|:---|:---|
| `_MCP_PROTOCOL_VERSION` | `"2024-11-05"` | MCP protocol version supported by the SDK. |
| `__version__` | `"0.1.2"` | Current SDK version. |
