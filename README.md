# Sentinel: Zero Trust Security for AI Agents

Sentinel is a security framework designed to enforce Zero Trust principles for AI agent tool execution. It acts as a deterministic, stateful policy enforcement point that wraps around agent tools, providing robust guardrails against unauthorized actions, mitigating data exfiltration risks, and protecting sensitive infrastructure from untrusted Large Language Models (LLMs).

## Core Concept

As LLM-powered agents are granted access to tools (e.g., APIs, databases, file systems), they introduce a significant security risk. The LLM's decision-making process is probabilistic, and it can be tricked via prompt injection into misusing tools.

Sentinel solves this by routing all tool calls through a trusted interceptor that applies deterministic, developer-defined security policies. It cryptographically binds permissions to every request, effectively isolating the untrusted agent from the secure execution environment.

## Architecture: The Trusted-Binding-Proxy (TBP) Model

The system is segmented into three distinct trust zones, enforcing security through both software logic and network topology.

1.  **Zone A: The Untrusted Client (The Agent)**

    - **Component:** `sentinel_sdk` (Python Package)
    - **Trust Level:** Zero. The agent has an API key but no direct knowledge of the secure execution environment or its rules.
    - **Function:**
      - Initiates a secure session via `/session/start`.
      - Wraps the agent's intended tool calls using the `SentinelClient`.
      - Forwards tool execution requests to the Interceptor.

2.  **Zone B: The Policy Enforcement Point (The Interceptor)**

    - **Component:** `sentinel-interceptor` (Rust)
    - **Trust Level:** High. This is the authoritative security engine.
    - **Function:**
      - **Authentication:** Validates the `X-Sentinel-Key` header against Supabase `projects` table.
      - **Configuration:** Loads granular Policies and Tool definitions dynamically from Supabase.
      - **Session Security:** Generates a unique, ephemeral **Ed25519 keypair** for each session.
      - **Handshake:** Registers the ephemeral public key with the MCP server upon session start.
      - **Enforcement:** Checks **Static Rules** (ALLOW/DENY) and **Dynamic Taint Rules** (Redis-backed state).
      - **Signing:** If approved, signs the request with the session-specific private key and forwards it to the MCP.

3.  **Zone C: The Secure Execution Environment (The MCP)**
    - **Component:** `mcp_server.py` (Python)
    - **Trust Level:** Verified Execution Only. Trusts nothing but a valid token signed by the registered session key.
    - **Protocol:** Custom JSON-RPC over HTTP.
    - **Function:**
      - **Dynamic Verification:** Verifies the JWT signature using the ephemeral public key registered for that specific session ID.
      - **Replay Protection:** Ensures tokens are not reused.
      - **Integrity:** Validates that arguments match the signed payload.
      - **Execution:** Executes the tool **only if all checks pass**.

## Getting Started: End-to-End Local Setup

These instructions cover running the backend infrastructure (Interceptor, MCP, Redis) using Docker Compose (recommended) or manually via shell scripts, and a local Python environment to run the agent.

### Prerequisites

- **Backend Services:** Choose one:
  - **Docker & Docker Compose:** [Install Docker Desktop](https://www.docker.com/products/docker-desktop/) (recommended)
  - **Manual Setup:** Redis installed locally + Python 3.10+ (see scripts in `./scripts/` directory)
- **Python 3.12:** The agent environment requires a standard Python 3.12 installation.

### Step 1: Configure Your Environment

1.  **Create `.env` file:** Create a file named `.env` in the project root. This file holds your API keys.

    ```ini
    # .env
    SENTINEL_API_KEY="<your_supabase_api_key>"
    SENTINEL_URL="http://localhost:8000"
    MCP_UPSTREAM_URL="http://localhost:9000"
    SUPABASE_PROJECT_URL="https://<your-project>.supabase.co"
    SUPABASE_SERVICE_ROLE_KEY="<your-service-role-key>"
    
    OPENROUTER_API_KEY="YOUR_OPENROUTER_API_KEY_HERE"
    OPENROUTER_MODEL="qwen/qwen3-next-80b-a3b-instruct"
    ```

2.  **Supabase Setup:** Ensure you have a Supabase project. The `projects` table must contain a record with your `api_key`.

### Step 2: Supabase (Managed Configuration)

Sentinel uses Supabase for policy storage. Ensure your `projects` table has the required API key and JSON configurations. No manual key generation is needed; keys are ephemeral and managed automatically.

### Step 3: Run the Backend Services

**Option A: Using Docker Compose** (Recommended)

With Docker running, use Docker Compose to build and start the Redis, Interceptor, and MCP containers.

```powershell
docker-compose up --build
```

**Option B: Running Services Separately** (Alternative)

If you prefer not to use Docker, you can run each service separately using the provided shell scripts (available in `./scripts/`).

### Step 4: Set Up the Agent Environment

In a **new terminal**, set up a clean Python 3.12 virtual environment.

```powershell
py -3.12 -m venv sentinel_env
.\sentinel_env\Scripts\activate
pip install -r requirements.txt
pip install -e sentinel_sdk -e sentinel_agent
```

### Step 5: Run the Experiment Suite

With the backend running and the agent environment activated, execute the test script.

```powershell
python sentinel_agent/examples/run_experiments.py
```

### Step 6 (Optional): Interactive Conversational Mode

For manual testing:

```powershell
python sentinel_agent/examples/conversational_agent.py --verbose
```

## System Configuration: Supabase

Sentinel's configuration is managed via Supabase.

- **`projects` table**:
   - `api_key`: The master key for the client.
   - `tools`: JSONB column defining available tools and their input schemas.
   - `policies`: JSONB column defining security rules.

- **Policies Structure**:
   - **`staticRules`**: Key-value map of `tool_name: "ALLOW" | "DENY"`.
   - **`taintRules`**: State-based rules.
     - `ADD_TAINT`: Tags the session when a tool is used.
     - `CHECK_TAINT`: Blocks execution if forbidden tags are present.
     - `BLOCK_SECOND`: Advanced sequence blocking (e.g., Read Sensitive -> Write External).

## Tool Classification: `rule_maker`

The `rule_maker` utility aids in classifying new tools into security classes (e.g., `SENSITIVE_READ`, `CONSEQUENTIAL_WRITE`) using an LLM classifier. This classification populates the Supabase `tools` definitions.

```bash
python rule_maker/src/classifier.py "send_email" "Sends email to recipient"
```

For detailed documentation, see `rule_maker/docs/README.md`.

## Integration with Your Own Agent

Integrating Sentinel into your own LangChain agent is seamless using the `SentinelClient`.

1.  **Initialize the Client**: Use the async context manager to handle session lifecycle automatically.
2.  **Fetch Tools**: `client.get_langchain_tools()` automatically converts policies into `StructuredTool` objects compatible with LangChain.
3.  **Run Agent**: Pass these tools directly to your agent executor.

**Example Code Snippet:**

```python
import os
from sentinel_sdk import SentinelClient
from langchain.agents import AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate

async def main():
    api_key = os.getenv("SENTINEL_API_KEY")
    interceptor_url = os.getenv("SENTINEL_URL", "http://localhost:8000")

    # SentinelClient manages the secure session handshake automatically
    async with SentinelClient(api_key=api_key, base_url=interceptor_url) as client:
        print(f"Secure Session ID: {client.session_id}")
        
        # 1. Get Secure Tools (Native LangChain Integration)
        # These tools wrap the proxy call and handle JSON-RPC execution
        tools = await client.get_langchain_tools()
        
        # 2. Setup your LangChain Agent
        llm = ChatOpenAI(model="gpt-4", temperature=0)
        prompt = PromptTemplate.from_template("Answer this: {input} using tools: {tools} ...")
        
        agent = create_react_agent(llm, tools, prompt)
        agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)
        
        # 3. Invoke
        # The tool calls are now interceptor-proxied and policy-enforced!
        await agent_executor.ainvoke({"input": "Read the production database configuration."})
```

## Next Steps & Refinements

The current version establishes a robust Zero Trust foundation. Future improvements include:

- **mTLS**: Securing the Interceptor-to-MCP link with mutual TLS.
- **Agent SDK**: Expanding error handling and providing retry strategies for blocked actions.
- **Dashboard**: A UI for viewing real-time session logs and policy violations (Audit Logs).
- **Policy Versioning**: Tracking changes to policies over time in Supabase.
