# Lilith Zero — Agentic Loop Example

Demonstrates Lilith Zero securing a multi-turn agentic loop — no framework dependency required.

## Scenario

An agent has access to three tools:

| Tool | Class | Behaviour |
|------|-------|-----------|
| `calculator` | Safe | Always allowed |
| `database` | Sensitive source | Allowed, adds `SENSITIVE_CONTEXT` taint |
| `web_search` | Network sink | **Blocked once `SENSITIVE_CONTEXT` taint is present** |
| `delete_record` | Destructive | **Statically denied** |

This models the core exfiltration threat: an agent that reads from a private data store and then tries to send results externally.

## Key Concepts

- **Taint tracking**: `database` adds `SENSITIVE_CONTEXT`; `web_search` is blocked by the taint rule.
- **Static deny**: `delete_record` is denied regardless of session state.
- **Audit log**: `drain_audit_logs()` returns a snapshot of all decisions after the loop completes.
- **Agentic realism**: The agent loop continues running safe tools even after the blocked call — mimicking how a real agent recovers and retries.

## Running

```bash
export LILITH_ZERO_BINARY_PATH=/path/to/lilith-zero
python agent.py
```
