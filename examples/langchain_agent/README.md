# LangChain + Lilith-Zero Demo

This example demonstrates how to secure a LangChain agent using Lilith-Zero.

## Setup

The database and tools have been configured to match the `demo/` environment:
- **Tools**: `web_search`, `read_data`, `read_sql_db`, `write_data`, `delete_db`
- **Policy**: 
  - `read` operations are ALLOWED
  - `write/delete` are BLOCKED
  - `web_search` is BLOCKED if data has been read (Taint Tracking)

## Running

Run the agent from the project root:

```bash
python3 examples/langchain_agent/agent.py
```

## Tools Available to Agent

1. **read_sql_db**: Execute SQL SELECT queries (e.g., "SELECT * FROM users")
2. **web_search**: Search the web (blocked after reading data)
3. **write_data**: Write to store (Always blocked)
4. **delete_db**: Delete database (Always blocked)
