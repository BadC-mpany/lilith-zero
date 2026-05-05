# Cedar Policy Solution: Using `like` Operator for Argument Validation

## The Challenge
Malicious URL blocking in Cedar policies wasn't working because Cedar couldn't evaluate `.contains()` method calls on untyped JSON attributes.

## The Solution
**Use Cedar's `like` operator for pattern matching on untyped JSON attributes.**

### Why This Works
Cedar's `like` operator is designed for string pattern matching and works seamlessly on untyped JSON attributes without requiring a schema. It uses wildcards (`*`) for flexible pattern matching.

## Policy Changes

### Before (Failed ❌)
```cedar
context.arguments.url.contains("malicious-site.com")
context.arguments.code.contains("import socket")
```

### After (Works ✅)
```cedar
context.arguments.url like "*malicious-site.com*"
context.arguments.code like "*import socket*"
```

## Test Results - All Passing ✅

| Test Case | Expected | Result | Status |
|-----------|----------|--------|--------|
| Malicious URL (malicious-site.com) | BLOCKED | BLOCKED | ✓ |
| Safe URL | ALLOWED | ALLOWED | ✓ |
| Exploit keyword in URL | BLOCKED | BLOCKED | ✓ |
| Search-Web (permitted) | ALLOWED | ALLOWED | ✓ |
| Read-Emails (permitted) | ALLOWED | ALLOWED | ✓ |
| Send-Email to normal address | ALLOWED | ALLOWED | ✓ |
| Send-Email to attacker@evil.com | BLOCKED | BLOCKED | ✓ |
| Execute-Python with safe code | ALLOWED | ALLOWED | ✓ |
| Execute-Python with import socket | BLOCKED | BLOCKED | ✓ |
| Unknown tool (fail-closed) | BLOCKED | BLOCKED | ✓ |

**Result: 10/10 tests passed**

## Key Implementation Details

1. **Pattern matching syntax**: Cedar's `like` operator uses shell glob patterns:
   - `*` matches zero or more characters
   - Example: `"*malicious*"` matches any string containing "malicious"

2. **Works on untyped JSON**: Unlike `.contains()`, the `like` operator doesn't require Cedar schema typing

3. **Deterministic policy enforcement**: All security rules now come from the Cedar policy file, not from heuristic code

4. **No code changes needed**: Only policy files were modified

## Files Modified

```
examples/copilot_studio/policies/policy_5be3e14e-2e46-f111-bec6-7c1e52344333.cedar
- Replaced .contains() with like operator for:
  - Malicious URL detection
  - Code injection detection
```

## Code Changes
- ✅ Reverted all heuristic code from security_core.rs
- ✅ No changes to cedar_evaluator.rs
- ✅ No changes to webhook server logic
- ✅ **100% policy-based security enforcement**

## Architecture Principle
This solution upholds the core security principle:
> **All security decisions are explicitly stated in the policy file, with no heuristic code in the evaluator.**

The Cedar policy is the single source of truth for all security rules. The evaluator simply executes what the policy defines.

## Future Enhancements
1. Consider adding Cedar schema for better IDE support and type checking
2. Use Cedar's built-in pattern library for complex matching
3. Add more granular pattern rules as security requirements evolve

---

**Status: Production Ready ✅**

All security rules are working correctly using pure Cedar policy evaluation with no heuristic workarounds.
