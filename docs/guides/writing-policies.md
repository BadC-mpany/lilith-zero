# Writing Policies

The security of your agent workflow depends on the quality of your policies. Lilith Zero uses a declarative YAML format to define what tools can run and how.

## Policy File Structure

A policy file (`policies.yaml`) consists of a list of definitions, each targeting a specific tool or command pattern.

```yaml
# policies.yaml
version: "1.0"
policies:
  - name: "Allow Python Math"
    command: "python"
    args: ["-c", "print(.*)"] # Regex matching
    isolation:
      network: false
      filesystem: "readonly"
  
  - name: "Allow Current Date"
    command: "date"
    args: []
```

## Policy Fields

### `name` (Required)
A human-readable description of the policy rule. Useful for audit logs.

### `command` (Required)
The exact binary name or path to the executable.
- Example: `python`, `/usr/bin/git`, `node`

### `args` (Optional)
A list of **Regular Expressions** that the arguments must match.
- If omitted or empty, **NO** arguments are allowed (strict mode).
- If you want to allow *any* argument, use `.*`.
- **Warning**: Be careful with `.*`. It allows `rm -rf /` if applied to `bash`.

### `isolation` (Optional)
Defines the sandbox constraints for this tool.

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `network` | `bool` | `false` | Allow network access? |
| `filesystem` | `string` | `"none"` | `"none"`, `"readonly"`, or `"readwrite"` (workspace only) |
| `cpu_limit` | `float` | `1.0` | Max CPU cores (e.g., 0.5 for half core) |
| `memory_limit_mb` | `int` | `512` | Max RAM in Megabytes |

## Example: Secure Python Calculator

To allow an agent to use Python for math but prevent it from accessing files or the network:

```yaml
policies:
  - name: "Safe Python Math"
    command: "python"
    # Allow "-c" followed by simple math expressions (digits, operators)
    args: 
      - "-c"
      - "^print\\([0-9+\\-*/\\s.]+\\)$" 
    isolation:
      network: false
      filesystem: "none"
```
