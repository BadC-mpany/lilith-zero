# Middleware Setup

This guide covers how to configure and run the `lilith-zero` middleware process.

## CLI Usage

The default usage wraps a command (like your agent script) and injects the middleware into its environment.

```bash title="Terminal"
lilith-zero [OPTIONS] -- <YOUR_COMMAND> [ARGS]
```

### Key Options

| Option | Description |
| :--- | :--- |
| `-p, --policy <FILE>` | Path to the YAML policy file. |
| `-u, --upstream-cmd <CMD>` | Command to launch the upstream tool server (e.g., "python"). |
| `-- <ARGS>` | Arguments for the upstream command (e.g., "server.py"). |

*Note: Configuration like log levels and security levels are handled via Environment Variables (e.g. `LILITH_LOG_LEVEL`, `LILITH_SECURITY_LEVEL`).*

## Production Deployment

### 1. Prepare your Environment
Ensure that `lilith-zero` is in your `PATH` or available at a known location.

### 2. Define the Policy
Create a loose `policy.yaml` first, run your agent in `--dry-run` mode to collect usage patterns, and then tighten the policy.

### 3. Run the Supervisor
Launch your agent under Lilith Zero's supervision.

```bash title="Terminal"
lilith-zero \
  --policy production-policy.yaml \
  --audit-log /var/log/lilith/audit.jsonl \
  -- python my_agent.py
```

## Logging & Observability

The audit log is a **line-delimited JSON (JSON-L)** file. Each line represents a tool execution attempt.

```json title="audit.jsonl"
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
