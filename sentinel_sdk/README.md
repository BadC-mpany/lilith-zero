# Sentinel SDK

The Sentinel SDK allows you to easily wrap your MCP Tool Servers with the Sentinel security middleware.

## Installation
```bash
pip install -e ./sentinel_sdk
```

## Usage
Wrap any MCP command to instantly apply security policies.

```python
from sentinel_sdk import Sentinel

client = Sentinel.start(
    upstream="python tools.py",
    policy="policy.yaml"
)

async with client:
    # Deterministic policy enforcement active here
    result = await client.execute_tool("read_db", {"q": "..."})
```

See `examples/` for attack simulation and enterprise deployment demos.
Requires `SENTINEL_BINARY_PATH` to be set to the Rust release binary.
