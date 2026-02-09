# Lilith Python SDK

The official Python client for the Lilith Security Middleware.

## Installation

```bash
pip install lilith-zero
```

*Note: This package requires the `Lilith` binary core. The SDK will attempt to find it automatically or guide you to install it.*

## Usage

### Zero-Config Connection
Lilith automatically discovers the binary on your PATH or in standard locations.

```python
from lilith_zero import Lilith
from lilith_zero.exceptions import PolicyViolationError

client = Lilith(
    upstream="python my_tool_server.py", # The command to run your tools
    policy="policy.yaml"                 # Security rules
)

async with client:
    try:
        tools = await client.list_tools()
        result = await client.call_tool("read_file", {"path": "secret.txt"})
    except PolicyViolationError as e:
        print(f"Security Alert: {e}")
```

### Manual Binary Path
If you need to point to a specific build (e.g. during development):

```python
client = Lilith(
    upstream="...",
    binary="/path/to/custom/Lilith" 
)
```

## Exceptions

- `PolicyViolationError`: Raised when the Policy Engine determines a request is unsafe (Static Rule, Taint Check, or Resource Access).
- `LilithConnectionError`: Raised if the middleware process cannot start or crashes.
- `LilithConfigError`: Raised if the binary is missing or arguments are invalid.

## License
Apache-2.0
