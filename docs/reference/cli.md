# CLI Reference

The `lilith-zero` binary is the core entry point for the middleware.

## Usage

```bash title="Terminal"
lilith-zero [OPTIONS] -- <COMMAND> [ARGS]...
```

## Options

### `--policy <FILE>`
- **Description**: Path to the YAML policy file defining allowed tools.
- **Env Var**: `ENV_POLICIES_YAML_PATH`

### `--upstream-cmd <CMD>`
- **Description**: The command to execute to start the upstream MCP server.

### `[ARGS]...`
- **Description**: Arguments to pass to the upstream command (must follow `--`).

### `--parent-pid <PID>`
- **Description**: (Internal) Used by the Supervisor mode to track the parent process ID. Do not use manually.

## Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | Success. |
| `1` | General Error (Configuration, Policy missing). |
| `101` | Middleware Panic (Bug). |
| `137` | Process Killed by Supervisor (OOM or Policy Violation). |
