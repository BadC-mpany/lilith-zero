# Python SDK Integration

This guide demonstrates how to use the **native Python SDK** (`lilith-zero`) to integrate security middleware directly into your Python-based agents.

Unlike the [generic integration](./secure-agent-integration.md) which requires managing standard I/O pipes manually, the Python SDK abstracts the entire lifecycle of the middleware process.

---

## Why use the SDK?

| Feature | Generic Integration (`mcp`) | Native SDK (`lilith-zero`) |
| :--- | :--- | :--- |
| **Process Management** | Manual (via `StdioServerParameters`) | **Automatic** (Context Manager) |
| **Error Handling** | Generic RPC errors | **Typed Exceptions** (`PolicyViolationError`) |
| **Session Security** | Manual HMAC validation (if needed) | **Transparent encryption/signing** |
| **Simplicity** | High (std_io plumbing) | **Maximum** (Pythonic API) |

## 1. Installation

```bash title="Terminal"
pip install lilith-zero
```

## 2. define a Policy

We will use the same **Public-Only Filesystem** policy as the previous guide.

```yaml title="policy.yaml"
staticRules:
  read_file: "ALLOW"
  write_file: "DENY"

taintRules:
  - tool: "read_file"
    action: "BLOCK"
    error: "Access denied: You can only read files in ./public/"
    pattern:
      not:
        tool_args_match:
          path: "./public/*"
```

## 3. The Agent Code

The `Lilith` class provides a clean async context manager that spins up the middleware, connects to the upstream tool, and manages the secure session.

```python title="native_agent.py"
import asyncio
from lilith_zero import Lilith, PolicyViolationError

async def main():
    print("Starting Secure Agent...")

    # The SDK handles the entire process lifecycle
    async with Lilith(
        upstream="npx -y @modelcontextprotocol/server-filesystem ./",
        policy="policy.yaml"
    ) as agent:
        
        # 1. Discovery
        tools = await agent.list_tools()
        print(f"Discovered {len(tools)} tools via secure introspection.")

        # 2. Allowed Operation
        print("\nReading public file...")
        try:
            # Direct tool call method
            result = await agent.call_tool("read_file", {"path": "./public/welcome.txt"})
            # The result is a clean dictionary, not a raw RPC frame
            print(f"   Success: {result['content'][0]['text'][:30]}...")
        except Exception as e:
            print(f"   Error: {e}")

        # 3. Blocked Operation
        print("\nAttempting to read private file...")
        try:
            await agent.call_tool("read_file", {"path": "./private/keys.env"})
        except PolicyViolationError as e:
            # The SDK raises specific exceptions for security events
            print(f"   BLOCKED BY LILITH: {e}")
        except Exception as e:
            print(f"   Unexpected error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
```

## 4. Running the Example

```bash title="Terminal"
# Ensure the simulated environment exists
mkdir public private
echo "Hello from SDK!" > public/welcome.txt
echo "SECRET_KEY" > private/keys.env

# Run the python script
python native_agent.py
```

### Output

```text title="Terminal"
Starting Secure Agent...
Discovered 5 tools via secure introspection.

Reading public file...
   Success: Hello from SDK!...

Attempting to read private file...
   BLOCKED BY LILITH: Access denied: You can only read files in ./public/
```

## Advanced: Type Checking

The SDK is fully typed, allowing you to use `mypy` or `pyright` to ensure your integration is robust.

```python title="agent.py"
from typing import Any
from lilith_zero import Lilith

# ... inside async function
    result: dict[str, Any] = await agent.call_tool(
        "read_file", 
        {"path": "./public/data.json"}
    )
```
