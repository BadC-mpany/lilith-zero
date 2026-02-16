# Writing Policies

The security of your agent workflow depends on the quality of your policies. Lilith Zero uses a declarative YAML format to define what tools can run and how permissions are handled.

## Policy File Structure

A policy file (`policy.yaml`) defines the security boundaries for a Lilith session.

```yaml
id: "my-policy"
customerId: "user-123"
name: "Production Security Policy"
version: 1

# 1. Static Access Control List (Tool Name -> Action)
staticRules:
  calculator: "ALLOW"
  read_file: "ALLOW"
  delete_file: "DENY"

# 2. Dynamic Taint Tracking Rules
taintRules:
  - tool: "read_file"
    action: "ADD_TAINT"
    tag: "SENSITIVE_DATA"

  - tool: "curl"
    action: "CHECK_TAINT"
    forbiddenTags: ["SENSITIVE_DATA"] # Block internet if we touched sensitive data
    error: "Cannot access internet with sensitive data."

# 3. Resource Access Rules
resourceRules:
  - uriPattern: "file:///tmp/*"
    action: "ALLOW"
  - uriPattern: "file:///etc/*"
    action: "BLOCK"

# 4. Global Settings
protectLethalTrifecta: true
```

## Sections

### `staticRules`
Simple Allow/Deny logic based on the tool name.
-   Key: Tool Name (e.g., `read_file`)
-   Value: `"ALLOW"` or `"DENY"`
-   **Default**: If a tool is not listed here, it is **DENIED** (Fail-Closed).

### `taintRules`
Manage information flow control using "Taints".
-   `tool`: The tool name this rule applies to.
-   `action`: 
    -   `ADD_TAINT`: Adds a tag to the session (e.g., `CONFIDENTIAL`).
    -   `CHECK_TAINT`: Checks if specific tags are present.
    -   `REMOVE_TAINT`: Clears a tag (sanitization).
    -   `BLOCK`: Unconditionally blocks the tool (useful with logic patterns).
-   `tag`: The tag to add or remove.
-   `forbiddenTags`: List of tags that, if present, will cause the tool to be blocked.
-   `requiredTags`: List of tags that MUST be present.

### `resourceRules`
Controls access to URI-based resources (files, URLs) if the protocol supports `resources`.
-   `uriPattern`: Glob pattern (e.g., `file:///home/user/public/*`).
-   `action`: `"ALLOW"` or `"BLOCK"`.

### `protectLethalTrifecta`
If set to `true`, Lilith automatically injects rules to prevent the "Lethal Trifecta":
1.  Accessing private data (`ACCESS_PRIVATE` taint).
2.  Accessing untrusted sources (`UNTRUSTED_SOURCE` taint).
3.  Exfiltrating data (calling tools classified as `EXFILTRATION`).

If a session accumulates both potentially dangerous taints, exfiltration tools are blocked.

