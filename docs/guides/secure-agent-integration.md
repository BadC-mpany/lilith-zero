# Secure Agent Integration

This guide demonstrates a production-grade integration of Lilith Zero with a **real AI Agent** and the **official Filesystem MCP Server**.

We will build a secure environment where an AI agent is allowed to **read files only from a public directory** (`./public`), but is strictly blocked from writing files or accessing private data.

!!! info "Using Python?"
    If you are building a Python agent, check out the [Native Python SDK Integration](./python-sdk-integration.md) for a cleaner, more idiomatic API.

---

## Architecture

```mermaid
graph LR
    A[AI Agent<br>(Python Client)] -->|Stdio| L[Lilith Zero<br>(Middleware)]
    L -->|Stdio| S[Filesystem MCP<br>(Upstream Server)]
    
    style A fill:#1e293b,stroke:#00e5ff,color:#fff
    style L fill:#0f172a,stroke:#00e676,stroke-width:2px,color:#fff
    style S fill:#1e293b,stroke:#64748b,color:#fff
```

## 1. Prerequisites

Ensure you have [uv](https://docs.astral.sh/uv/) and [Node.js](https://nodejs.org/) installed.

```bash title="Terminal"
# Install the Python MCP SDK
uv pip install mcp lilith-zero
```

## 2. The Target: Filesystem Server

We will use the official `@modelcontextprotocol/server-filesystem`. By default, this server allows full read/write access to the directories you expose.

```bash title="Terminal"
# Standard insecure usage (DO NOT RUN)
npx -y @modelcontextprotocol/server-filesystem ./
```

If an agent were connected to this directly, it could delete files, overwrite source code, or exfiltrate private keys.

## 3. The Policy

We will define a policy that:
1.  **Allows** `list_directory` globally.
2.  **Allows** `read_file` **ONLY** if the path starts with `./public/`.
3.  **Blocks** `write_file` and everything else.

Create `policy.yaml`:

```yaml title="policy.yaml"
id: "secure-fs-policy"
customerId: "demo-user"
name: "Public-Only Filesystem"
version: 1

# 1. Base ACLs: Allow read/list, Deny write
staticRules:
  list_directory: "ALLOW"
  read_file: "ALLOW"      # Conditional logic applied in taintRules
  write_file: "DENY"      # Hard block
  get_file_info: "ALLOW"

# 2. Granular Logic: Enforce path restrictions
taintRules:
  - tool: "read_file"
    action: "BLOCK"
    error: "Access denied: You can only read files in ./public/"
    pattern:
      # Block if the arguments DO NOT match the allowed pattern
      not:
        tool_args_match:
          path: "./public/*"

protectLethalTrifecta: true
```

## 4. The Agent (Client)

We'll use a Python script as our "Agent". In a real scenario, this would be LangChain, AutoGen, or a Claude Desktop extension.

Instead of connecting directly to the server, we configure the client to launch `lilith-zero`.

Create `agent.py`:

```python title="agent.py"
import asyncio
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def run_agent():
    # 1. Configure the connection 
    # We launch 'lilith-zero' which wraps the actual server
    server_params = StdioServerParameters(
        command="lilith-zero",
        args=[
            "--policy", "policy.yaml",
            "--upstream-cmd", "npx",
            "--", # Separator for upstream args
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "./"  # Expose current directory to the middleware
        ],
        env=None
    )

    print("Connecting to Secure Middleware...")
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # Scenario A: List files (Allowed)
            print("\nListing directory...")
            ls_result = await session.call_tool("list_directory", {"path": "./"})
            print(f"   Success: Found {len(ls_result.content)} items")

            # Scenario B: Read PUBLIC file (Allowed)
            print("\nzzz Reading ./public/welcome.txt...")
            try:
                read_result = await session.call_tool("read_file", {"path": "./public/welcome.txt"})
                print(f"   Success: {read_result.content[0].text[:20]}...")
            except Exception as e:
                print(f"   Error: {e}")

            # Scenario C: Read PRIVATE file (Blocked by Policy)
            print("\nAttempting to read ./private/secrets.env...")
            try:
                await session.call_tool("read_file", {"path": "./private/secrets.env"})
                print("   [CRITICAL FAIL] Unrestricted access!")
            except Exception as e:
                # The policy violation comes back as an MCP error
                print(f"   Blocked: {e}")

if __name__ == "__main__":
    asyncio.run(run_agent())
```

## 5. Execution

First, set up the simulated environment:

```bash title="Terminal"
mkdir public private
echo "Welcome!" > public/welcome.txt
echo "API_KEY=123" > private/secrets.env
```

Now run the agent:

```bash title="Terminal"
python agent.py
```

### Expected Output

You will see Lilith Zero strictly enforcing the boundaries:

```text title="Output"
Connecting to Secure Middleware...

Listing directory...
   Success: Found 2 items

zzz Reading ./public/welcome.txt...
   Success: Welcome!...

Attempting to read ./private/secrets.env...
   Blocked: Access denied: You can only read files in ./public/
```

## Summary

In this example, your Agent **thinks** it has full access to the filesystem (standard `npx` server), but **Lilith Zero** silently intercepts every request.

- **Zero Code Changes** to the upstream server.
- **Minimal Configuration** in the agent (just change the startup command).
- **Hard Security Guarantees** verified by the policy engine.
