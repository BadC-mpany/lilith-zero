# Quickstart: Hello World

Let's build a secure "Hello World" agent using Lilith Zero. We will create a simple MCP tool server and a client (Agent), then enforce a policy that allows one tool but blocks another.

## 1. Create the Tool Server

Create a file named `server.py`. This script simulates an MCP server with two tools: `ping` (safe) and `read_secret` (sensitive).

```python
from mcp_helper import MCPServer # You can use any MCP SDK here

server = MCPServer("MinimalServer")

@server.tool
def ping() -> str:
    """Simple health check."""
    return "pong"

@server.tool
def read_secret() -> str:
    """Reads sensitive data."""
    return "SECRET_DATA_123"

if __name__ == "__main__":
    server.run()
```

*Note: For this example, we assume a simple helper `MCPServer`, but you can use the official Python MCP SDK.*

## 2. Define the Policy

Create a file named `policy.yaml`. We will **ALLOW** `ping` but **DENY** `read_secret`.

```yaml
id: "quickstart-policy"
customerId: "local-user"
name: "Quickstart Policy"
version: 1

staticRules:
  ping: "ALLOW"
  read_secret: "DENY"

taintRules: []
resourceRules: []
protectLethalTrifecta: false
```

## 3. Create the Client (Agent)

Create a file named `agent.py` that uses the Lilith SDK to connect to the server securely.

```python
import asyncio
from lilith_zero import Lilith
from lilith_zero.exceptions import PolicyViolationError

async def main():
    # Start Lilith, which wraps the upstream server
    async with Lilith(
        upstream="python server.py", 
        policy="policy.yaml"
    ) as lilith:
        
        # 1. Call an ALLOWED tool
        print("Calling 'ping'...")
        result = await lilith.call_tool("ping", {})
        print(f"Result: {result}")

        # 2. Call a DENIED tool
        print("\nCalling 'read_secret'...")
        try:
            await lilith.call_tool("read_secret", {})
        except PolicyViolationError as e:
            print(f"Blocked: {e}")

if __name__ == "__main__":
    asyncio.run(main())
```

## 4. Run It

```bash
python agent.py
```

### Expected Output

```text
Calling 'ping'...
Result: pong

Calling 'read_secret'...
Blocked: Tool 'read_secret' is forbidden by static policy
```

You have successfully intercepted and blocked a tool call using Lilith Zero!

## Next Steps

-   Learn how to [Write granular policies](../guides/writing-policies.md).
-   Explore the [Architecture](../concepts/architecture.md).
