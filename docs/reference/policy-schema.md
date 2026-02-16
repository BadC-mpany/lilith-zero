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
| `tool` | `string` | Conditional | Tool name this rule applies to. Either `tool` or `toolClass` must be set. |
| `toolClass` | `string` | Conditional | Tool classification category (e.g., `"EXFILTRATION"`, `"DATA_ACCESS"`). Either `tool` or `toolClass` must be set. |
| `action` | `string` | Yes | One of: `ADD_TAINT`, `CHECK_TAINT`, `REMOVE_TAINT`, `BLOCK`. |
| `tag` | `string` | Conditional | Tag to add or remove. Required for `ADD_TAINT` / `REMOVE_TAINT`. |
| `forbiddenTags` | `list<string>` | No | If any of these tags are present, block the tool. |
| `requiredTaints` | `list<string>` | No | All of these tags must be present to allow the tool. |
| `error` | `string` | No | Custom error message on violation. |
| `pattern` | `LogicCondition` | No | Conditional logic pattern for rule evaluation (see below). |
| `exceptions` | `list<RuleException>` | No | Exception conditions that override the rule (see below). |

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

## `LogicCondition` — Conditional Rule Evaluation

Taint rules support a typed condition language for expressing complex logic. Conditions are specified in the `pattern` field of a `TaintRule` or the `when` field of a `RuleException`.

### Logical Operators

| Operator | Syntax | Description |
|:---|:---|:---|
| **AND** | `and: [cond1, cond2, ...]` | All conditions must be true. |
| **OR** | `or: [cond1, cond2, ...]` | At least one condition must be true. |
| **NOT** | `not: cond` | Negates the condition. |

### Comparison Operators

| Operator | Syntax | Description |
|:---|:---|:---|
| **Equals** | `==: [lhs, rhs]` | Checks equality between two values. |
| **Not Equals** | `!=: [lhs, rhs]` | Checks inequality. |
| **Greater Than** | `>: [lhs, rhs]` | Numeric greater-than comparison. |
| **Less Than** | `<: [lhs, rhs]` | Numeric less-than comparison. |

### Domain-Specific Operators

| Operator | Syntax | Description |
|:---|:---|:---|
| **Tool Args Match** | `tool_args_match: <schema>` | Matches tool arguments against a JSON schema. |
| **Literal** | `true` / `false` | Constant boolean value. |

### Value References

Values in comparison operators can be:

| Type | Syntax | Example |
|:---|:---|:---|
| **Variable** | `{var: "path"}` | `{var: "tool_name"}`, `{var: "args.path"}` |
| **String** | `"value"` | `"read_file"` |
| **Number** | `123` | `42`, `3.14` |
| **Boolean** | `true` / `false` | `true` |
| **Null** | `null` | `null` |

### Examples

??? example "Block network tools only when sensitive data was accessed"

    ```yaml
    taintRules:
      - tool: "curl"
        action: "BLOCK"
        pattern:
          and:
            - {==: [{var: "tool_name"}, "curl"]}
            - {not: {==: [{var: "session.taints"}, []]}}
        error: "Network access denied: session holds taints."
    ```

??? example "Allow a tool only for specific argument patterns"

    ```yaml
    taintRules:
      - tool: "read_file"
        action: "ALLOW"
        pattern:
          tool_args_match:
            path: "/tmp/*"
    ```

??? example "Complex OR condition with exceptions"

    ```yaml
    taintRules:
      - toolClass: "EXFILTRATION"
        action: "BLOCK"
        pattern:
          or:
            - {==: [{var: "session.taint_count"}, 0]}
            - {not: true}
        error: "Exfiltration blocked."
        exceptions:
          - when:
              ==: [{var: "tool_name"}, "approved_upload"]
            reason: "Approved upload tool is exempt."
    ```

## `RuleException` Object

Exceptions allow overriding a rule under specific conditions.

| Field | Type | Required | Description |
|:---|:---|:---|:---|
| `when` | `LogicCondition` | Yes | Condition that must be true for the exception to apply. |
| `reason` | `string` | No | Documentation of why this exception exists. |

## `ResourceRule` Object

| Field | Type | Required | Description |
|:---|:---|:---|:---|
| `uriPattern` | `string` | Yes | Glob pattern for the resource URI. |
| `action` | `string` | Yes | `"ALLOW"` or `"BLOCK"`. |
| `exceptions` | `list<RuleException>` | No | Exception conditions for this resource rule. |
| `taintsToAdd` | `list<string>` | No | Taints to add to the session when this resource is accessed. |

```yaml
resourceRules:
  - uriPattern: "file:///tmp/*"
    action: "ALLOW"
  - uriPattern: "file:///etc/*"
    action: "BLOCK"
  - uriPattern: "file:///home/user/secrets/*"
    action: "ALLOW"
    taintsToAdd: ["SENSITIVE_DATA"]
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
