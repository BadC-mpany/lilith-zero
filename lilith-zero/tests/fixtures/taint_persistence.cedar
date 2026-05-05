// Cedar policy for testing taint persistence across hook invocations.
// This policy defines a security model where:
// 1. taint_source_tool adds UNTRUSTED_DATA taint
// 2. check_untrusted_tool denies if UNTRUSTED_DATA taint is present
// 3. remove_taint_tool removes the UNTRUSTED_DATA taint
// 4. All other tools (allowed_tool, neutral_tool) are permitted without taint effects

// ============================================================================
// Rule 1: Allow taint_source_tool and add UNTRUSTED_DATA taint
// ============================================================================
// This rule permits the tool call and marks it with an annotation that causes
// the SecurityCore to add the UNTRUSTED_DATA taint to the session state.
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"tool-taint_source_tool"
)
@id("add_taint:UNTRUSTED_DATA");

// ============================================================================
// Rule 2: Deny check_untrusted_tool if UNTRUSTED_DATA taint is present
// ============================================================================
// This rule forbids the tool call when the UNTRUSTED_DATA taint is active,
// testing the core taint persistence: if the taint was added in a previous
// invocation and persisted to disk, it should be present in context here.
forbid(
    principal,
    action == Action::"tools/call",
    resource == Resource::"tool-check_untrusted_tool"
) when {
    context.taints.contains("UNTRUSTED_DATA")
};

// ============================================================================
// Rule 3: Allow remove_taint_tool and remove UNTRUSTED_DATA taint
// ============================================================================
// This rule permits the tool call and marks it to remove the taint.
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"tool-remove_taint_tool"
)
@id("remove_taint:UNTRUSTED_DATA");

// ============================================================================
// Rule 4: Permit allowed_tool unconditionally (no taint effects)
// ============================================================================
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"tool-allowed_tool"
);

// ============================================================================
// Rule 5: Permit neutral_tool unconditionally (no taint effects)
// ============================================================================
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"tool-neutral_tool"
);

// ============================================================================
// Default deny: any tool not explicitly permitted is denied
// ============================================================================
// Cedar's default is to deny if no permit rule matches, so this is implicit.
// All other tools will be denied.
