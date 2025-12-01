# Sentinel: Zero Trust Security for AI Agents

Sentinel is a security framework designed to enforce Zero Trust principles for AI agent tool execution. It acts as a deterministic, stateful policy enforcement point that wraps around agent tools, providing robust guardrails against unauthorized actions, mitigating data exfiltration risks, and protecting sensitive infrastructure from untrusted Large Language Models (LLMs).

## Core Concept

As LLM-powered agents are granted access to tools (e.g., APIs, databases, file systems), they introduce a significant security risk. The LLM's decision-making process is probabilistic, and it can be tricked via prompt injection into misusing tools.

Sentinel solves this by routing all tool calls through a trusted interceptor that applies deterministic, developer-defined security policies. It cryptographically binds permissions to every request, effectively isolating the untrusted agent from the secure execution environment.

## Architecture: The Trusted-Binding-Proxy (TBP) Model

The system is segmented into three distinct trust zones, enforcing security through both software logic and network topology.

1.  **Zone A: The Untrusted Client (The Agent)**

    - **Component:** `sentinel_sdk.py` (`SentinelSecureTool`)
    - **Trust Level:** Zero. The agent has an API key but no direct knowledge of the secure execution environment or its rules.
    - **Function:** Wraps the agent's intended tool calls and forwards them to the Interceptor for approval.

2.  **Zone B: The Policy Enforcement Point (The Interceptor)**

    - **Component:** `interceptor_service.py`
    - **Trust Level:** High. This is the authoritative security engine.
    - **Function:**
      - Authenticates the agent via its API key.
      - Loads security rules from `policies.yaml`.
      - Checks **Static Rules** (simple `ALLOW`/`DENY` on a tool).
      - Checks **Dynamic Rules** by tracking the session's "taint state" in Redis (e.g., blocking a web search if the session has accessed sensitive data).
      - If approved, mints a short-lived JSON Web Signature (JWS) token that cryptographically binds the permission to the exact tool arguments.
      - Proxies the request and the JWS token to the secure execution environment.

3.  **Zone C: The Secure Execution Environment (The MCP)**
    - **Component:** `mcp_server.py`
    - **Trust Level:** Verified Execution Only. Trusts nothing but a valid token.
    - **Function:**
      - Verifies the JWS token's cryptographic signature using a public key.
      - Performs replay protection by checking the token's nonce (`jti`) against a Redis cache.
      - Validates parameter integrity by comparing a hash of the received arguments against the hash in the token, preventing in-transit tampering (TOCTOU attacks).
      - Executes the tool **only if all checks pass**.

## Getting Started: End-to-End Local Setup

These instructions use Docker Compose to run the backend infrastructure (Interceptor, MCP, Redis) and a local Python environment to run the agent.

### Prerequisites

- **Docker & Docker Compose:** Required to run the backend services. [Install Docker Desktop](https://www.docker.com/products/docker-desktop/).
- **Python 3.12:** The agent environment requires a standard Python 3.12 installation.

### Step 1: Configure Your Environment

1.  **Create `.env` file:** Create a file named `.env` in the project root. This file holds your API keys. You must add your OpenRouter API key.

    ```ini
    # .env
    SENTINEL_API_KEY="sk_live_demo_123"
    SENTINEL_URL="http://localhost:8000"
    OPENROUTER_API_KEY="YOUR_OPENROUTER_API_KEY_HERE"
    OPENROUTER_MODEL="qwen/qwen3-next-80b-a3b-instruct"
    ```

2.  **Review `policies.yaml`:** This file defines all security rules. The default configuration is set up for the demo, including the API key `sk_live_demo_123`.

### Step 2: Generate Cryptographic Keys

The Interceptor and MCP use an Ed25519 keypair to sign and verify requests. Run this command once to create the `secrets` directory and the key files.

```powershell
# In a new terminal
python -m venv temp_env
.\temp_env\Scripts\activate
pip install cryptography
python src/key_gen.py
deactivate
rmdir /s /q temp_env
```

### Step 3: Run the Backend Services

With Docker running, use Docker Compose to build and start the Redis, Interceptor, and MCP containers.

```powershell
docker-compose up --build
```

The services are now running. The Interceptor is available at `http://localhost:8000` and the MCP at `http://localhost:9000`. You can leave this terminal running.

### Step 4: Set Up the Agent Environment

In a **new terminal**, set up a clean Python 3.12 virtual environment. This is crucial for avoiding dependency conflicts.

1.  **Create the virtual environment:**

    ```powershell
    py -3.12 -m venv sentinel_env
    ```

2.  **Activate the environment:**

    ```powershell
    .\sentinel_env\Scripts\activate
    ```

3.  **Install dependencies:**
    ```powershell
    pip install -r requirements.txt
    ```

### Step 5: Run the Experiment Suite

With the backend running and the agent environment activated, execute the test script.

```powershell
python run_experiments.py
```

You will see the formatted output for each of the four test scenarios, demonstrating the Sentinel system allowing, tainting, and blocking actions as designed.

### Step 6 (Optional): Interactive Conversational Mode

For manual testing and interactive exploration of the security policies, you can use the `conversational_agent.py` script. This provides a professional, chat-like interface to talk directly with the Sentinel-secured agent.

1.  **Ensure your backend is running** (`docker-compose up`).
2.  **Activate the agent environment**:
    ```powershell
    .\sentinel_env\Scripts\activate
    ```
3.  **Run the Agent:**

    *   **Default (Clean) Mode:** For a simple, clean chat experience.
        ```powershell
        python conversational_agent.py
        ```
    *   **Verbose (Debug) Mode:** To see the agent's full thought process, security checks, and detailed LLM inputs/outputs, use the `--verbose` flag.
        ```powershell
        python conversational_agent.py --verbose
        ```

## System Configuration: `policies.yaml`

This file is the control plane for the entire security system.

- **`customers`:** Defines API keys and maps them to a policy. The `mcp_upstream_url` must use the Docker service name (e.g., `http://mcp_server:9000/execute`).
- **`policies`:** A list of named policies that can be assigned to customers.
  - **`static_rules`:** A simple map of `tool_name: ALLOW` or `tool_name: DENY`. Acts as a primary access control list.
  - **`taint_rules`:** Defines the dynamic, stateful logic.
    - **`ADD_TAINT`:** If `tool` is used, apply the specified `tag` to the session.
    - **`CHECK_TAINT`:** Before allowing `tool` to run, check if the session has any of the `forbidden_tags`. If so, block the request and return the specified `error` message.

## Integration with Your Own Agent

Integrating Sentinel into your own LangChain agent is straightforward.

1.  Ensure your agent's environment has access to the Sentinel source (`src`) or has it installed as a package.
2.  Use the `sentinel_tool_loader` to create secure tool instances.
3.  Set the `session_id` before starting your agent loop.

**Example Code Snippet:**

```python
import os
import uuid
from src.sentinel_tool_loader import load_sentinel_tools
from langchain.agents import AgentExecutor, create_react_agent
# ... your LLM and prompt setup

# --- Your Agent Setup ---
# 1. Ensure SENTINEL_API_KEY is in the environment
API_KEY = os.getenv("SENTINEL_API_KEY")
if not API_KEY:
    raise ValueError("SENTINEL_API_KEY not set")

# 2. Generate a unique ID for this conversation
session_id = str(uuid.uuid4())

# 3. Load the tools allowed by your API key
secure_tools = load_sentinel_tools(api_key=API_KEY)

# 4. Set the session ID on each tool
for tool in secure_tools:
    tool.set_session_id(session_id)

# 5. Create your agent as you normally would
# llm = ...
# prompt = ...
agent = create_react_agent(llm, secure_tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=secure_tools, verbose=True)

# 6. Run your agent
agent_executor.invoke({"input": "Your user's first prompt"})
```

## Next Steps & Refinements

The current MVP is fully functional but can be hardened and scaled for production use.

- **Dynamic Tool Loading:** Refactor `mcp_server.py` to dynamically load tool functions from a directory, rather than using hardcoded `if/else` statements.
- **Structured Logging:** Replace all `print()` statements in the services with Python's `logging` module for production-grade, searchable logs.
- **Agent Error Handling:** Refine the agent's prompt or the `AgentExecutor` configuration (`max_iterations`) to handle `SECURITY_BLOCK` errors more gracefully instead of retrying indefinitely.
- **Implement mTLS:** For maximum security, the connection between the Interceptor and the MCP should be secured with mutual TLS (mTLS) in addition to the JWS token verification.
- **Configuration Management:** For a large-scale deployment, policies in `policies.yaml` could be moved to a dedicated database or a service like HashiCorp Vault.
