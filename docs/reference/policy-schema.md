# Policy Schema Reference

Complete reference for the `policy.yaml` configuration file.

## Top-Level Fields

| Field | Type | Required | Description |
|:---|:---|:---|:---|
| `id` | `string` | Yes | Unique identifier for this policy. |
| `customerId` | `string` | Yes | Customer or tenant identifier. |
| `name` | `string` | Yes | Human-readable policy name. |
| `version` | `integer` | Yes | Policy schema version (currently `1`). |
| `staticRules` | `map<string, string>` | No | Tool name → `"ALLOW"` or `"DENY"`. |
| `taintRules` | `list<TaintRule>` | No | Dynamic information-flow rules. |
| `resourceRules` | `list<ResourceRule>` | No | URI-pattern access control rules. |
| `protectLethalTrifecta` | `boolean` | No | Auto-inject Lethal Trifecta protection. Default: `false`. |

## `staticRules`

Simple allowlist / blocklist keyed by tool name.

```yaml
staticRules:
  calculator: "ALLOW"
  read_file: "ALLOW"
  delete_file: "DENY"
```

**Default behavior**: Any tool not listed is **DENIED** (fail-closed).

## `TaintRule` Object

| Field | Type | Required | Description |
|:---|:---|:---|:---|
| `tool` | `string` | Yes | Tool name this rule applies to. |
| `action` | `string` | Yes | One of: `ADD_TAINT`, `CHECK_TAINT`, `REMOVE_TAINT`, `BLOCK`. |
| `tag` | `string` | Conditional | Tag to add or remove. Required for `ADD_TAINT` / `REMOVE_TAINT`. |
| `forbiddenTags` | `list<string>` | No | If any of these tags are present, block the tool. |
| `requiredTags` | `list<string>` | No | All of these tags must be present to allow the tool. |
| `error` | `string` | No | Custom error message on violation. |

```yaml
taintRules:
  - tool: "read_file"
    action: "ADD_TAINT"
    tag: "SENSITIVE_DATA"

  - tool: "curl"
    action: "CHECK_TAINT"
    forbiddenTags: ["SENSITIVE_DATA"]
    error: "Cannot access internet after reading sensitive data."
```

## `ResourceRule` Object

| Field | Type | Required | Description |
|:---|:---|:---|:---|
| `uriPattern` | `string` | Yes | Glob pattern for the resource URI. |
| `action` | `string` | Yes | `"ALLOW"` or `"BLOCK"`. |

```yaml
resourceRules:
  - uriPattern: "file:///tmp/*"
    action: "ALLOW"
  - uriPattern: "file:///etc/*"
    action: "BLOCK"
```

## `protectLethalTrifecta`

When set to `true`, Lilith Zero automatically injects taint rules that:

1. Tag tools with `ACCESS_PRIVATE` when they access sensitive data.
2. Tag tools with `UNTRUSTED_SOURCE` when they process untrusted input.
3. Block any tool classified as `EXFILTRATION` if the session holds both taints.

```yaml
protectLethalTrifecta: true
```

## Minimal Example

```yaml
id: "minimal"
customerId: "dev"
name: "Development Policy"
version: 1
staticRules:
  ping: "ALLOW"
protectLethalTrifecta: true
```
