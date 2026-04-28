# Native Cedar Policies for Lilith-Zero

Lilith-Zero now supports native Cedar policies (`.cedar` files) for formally verified security enforcement. This allows for more complex logic than the legacy YAML format.

## MCP Policy Schema

All Cedar policies in Lilith-Zero are grounded in the following entity and context structure:

### Entities
- **Principal:** `Session::"SESSION_ID"` (The current agent session)
- **Action:** `Action::"mcp/method"` (e.g., `Action::"tools/call"`, `Action::"resources/read"`)
- **Resource:** `Resource::"tool_name"` or `Resource::"uri"`

### Context
The `context` record provides detailed metadata about the request:

| Field | Type | Description |
|-------|------|-------------|
| `taints` | `Set<String>` | Current session taints (e.g., `SECRET`, `UNTRUSTED`). |
| `paths` | `Set<String>` | All canonicalized paths found in the request arguments. |
| `path` | `String` | The specific path being evaluated (for `resources/read`). |
| `args` | `Record` | The raw JSON arguments passed to the tool. |
| `classes` | `Set<String>` | Security classes assigned to the tool (e.g., `EXFILTRATION`). |

## Example: Lethal Trifecta Protection

```cedar
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    context.taints.contains("SECRET") &&
    context.taints.contains("UNTRUSTED") &&
    context.classes.contains("EXFILTRATION")
};
```

## Example: Mandatory Tainting

To add a taint, use a permit rule with an ID formatted as `add_taint:TAG:NONCE`.

```cedar
@id("add_taint:SECRET:1")
permit(
    principal,
    action == Action::"resources/read",
    resource
) when {
    context.path like "*/infra/*"
};
```
