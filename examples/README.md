# Sentinel Demo: LangChain & Observability

This demo showcases Sentinel's ability to provide deterministic security and observability to a LangChain-based agent.

## Components
1. **`tools_server.py`**: A `FastMCP` server providing database and communication tools.
2. **`demo_policy.yaml`**: A Sentinel policy that implements **Taint Tracking**:
   - `read_database` -> Adds a `PII` taint to the session.
   - `send_email` -> Blocked if a `PII` taint is present (preventing exfiltration).
3. **`observability_demo.py`**: A LangChain agent that uses these tools through Sentinel.

## Prerequisites
- **Python Dependencies**:
  ```bash
  pip install langchain langchain-openai python-dotenv fastmcp
  ```
- **OpenRouter API Key**:
  Provide an API key via environment variable:
  ```bash
  # Windows
  set OPENROUTER_API_KEY=your_key_here
  # Or create a .env file
  ```

## Running the Demo
```bash
python examples/observability_demo.py
```

## What to Observe
- **Deterministic Security**: The agent is allowed to read data, but as soon as it tries to "send" data to an external service *after* reading, Sentinel blocks the call.
- **Audit Logs**: Watch the `stderr` output (printed to console) for structured JSON logs. Every decision is logged with:
  - `event_type`: "Decision"
  - `tool`: The tool being called
  - `decision`: "Allowed" or "Denied"
  - `session_id`: Unique HMAC-signed ID for the session
- **Spotlighting**: Sentinel wraps tool outputs in randomized delimiters (e.g., `<<<SENTINEL_DATA_START:XXXX>>>`) to prevent the LLM from being tricked by "fake" tool outputs in its prompt.
