# Sentinel SDK

The Sentinel SDK allows you to easily wrap your MCP Tool Servers with the Sentinel security middleware.

## Installation

```bash
pip install sentinel-sdk
```

## Usage

```python
from sentinel_sdk import Sentinel
from langchain_mcp import load_mcp_tools

# Wrap your tool server execution
config = Sentinel.wrap_command(
    upstream_cmd="python",
    upstream_args=["my_tools.py"],
    policies_path="policy.yaml"
)

# Load tools into LangChain (or any MCP client)
tools = load_mcp_tools(**config)
```
