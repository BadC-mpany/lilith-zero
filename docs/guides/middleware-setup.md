# Middleware Setup

This guide covers how to configure and run the `lilith-zero` middleware process.

## CLI Usage

The default usage wraps a command (like your agent script) and injects the middleware into its environment.

```bash
lilith-zero [OPTIONS] -- <YOUR_COMMAND> [ARGS]
```

### Key Options

| Option | Description | Default |
| :--- | :--- | :--- |
| `-p, --policy <FILE>` | Path to the YAML policy file. | `policies.yaml` |
| `-a, --audit-log <FILE>` | Path to write the JSON-L audit log. | `audit.jsonl` |
| `--enforce` | Enable strict enforcement (Hard Fail). | `true` |
| `--dry-run` | Log violations but do not block them (Audit Mode). | `false` |

## Production Deployment

### 1. Prepare your Environment
Ensure that `lilith-zero` is in your `PATH` or available at a known location.

### 2. Define the Policy
Create a loose `policies.yaml` first, run your agent in `--dry-run` mode to collect usage patterns, and then tighten the policy.

### 3. Run the Supervisor
Launch your agent under Lilith Zero's supervision.

```bash
# Example: Running a LangChain agent
lilith-zero --policy production-policies.yaml --audit-log /var/log/lilith/audit.jsonl -- python my_agent.py
```

## Logging & Observability

The audit log is a **line-delimited JSON (JSON-L)** file. Each line represents a tool execution attempt.

```json
{
  "timestamp": "2023-10-27T10:00:00Z",
  "event": "tool_execution",
  "status": "blocked",
  "reason": "policy_violation",
  "command": "curl",
  "args": ["http://evil.com"],
  "policy_name": null
}
```
