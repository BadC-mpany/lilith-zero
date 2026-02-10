# CLI Reference

The `lilith-zero` binary is the core entry point for the middleware.

## Usage

```bash
lilith-zero [OPTIONS] -- <COMMAND> [ARGS]...
```

## Options

### `--policy <FILE>`
- **Description**: Path to the YAML policy file defining allowed tools.
- **Default**: `policies.yaml`
- **Env Var**: `LILITH_POLICY`

### `--audit-log <FILE>`
- **Description**: Path to the output audit log file (JSON-L format).
- **Default**: `audit.jsonl`
- **Env Var**: `LILITH_AUDIT_LOG`

### `--enforce`
- **Description**: If set, Lilith Zero will **block** any policy violations. If unset (or if `--dry-run` is used), it will only log them.
- **Default**: `true` (Enforcement is ON by default).

### `--dry-run`
- **Description**: Alias for disabling enforcement. Useful for learning tool usage patterns before locking them down.

### `--parent-pid <PID>`
- **Description**: (Internal) Used by the Supervisor mode to track the parent process ID. Do not use manually.

## Exit Codes

- `0`: Success.
- `1`: General Error (Configuration, Policy missing).
- `101`: Middleware Panic (Bug).
- `137`: Process Killed by Supervisor (OOM or Policy Violation).
