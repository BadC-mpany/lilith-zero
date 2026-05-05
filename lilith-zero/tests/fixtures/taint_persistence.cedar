// Cedar policy for testing taint persistence across hook invocations.
//
// Taint conventions (must match SecurityCore taint extraction logic):
//   @id("add_taint:<TAG>:<discriminator>")    — adds taint on ALLOW
//   @id("remove_taint:<TAG>:<discriminator>") — removes taint on ALLOW
//   forbid(...) when { context.taints.contains("<TAG>") } — blocks when taint present
//
// NOTE: Cedar assigns auto-incremented PolicyIds (policy0, policy1, …).
// Taint directives live in the @id *annotation*, read via
// get_policy_annotation(policy_id, "id"). The colon-separated suffix after the
// taint name (e.g. ":rule") is required — split_once(':') uses it as a
// discriminator and the taint name is the left-hand side.
//
// Annotations must appear BEFORE the permit/forbid keyword.

// taint_source_tool: allowed, adds UNTRUSTED_DATA taint.
@id("add_taint:UNTRUSTED_DATA:rule")
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"taint_source_tool"
);

// check_untrusted_tool: permitted by default; the forbid rule below overrides
// this permit when the UNTRUSTED_DATA taint is present. Cedar is deny-by-default,
// so without this permit the tool would always be denied regardless of taints.
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"check_untrusted_tool"
);

// check_untrusted_tool: blocked when UNTRUSTED_DATA taint is active (overrides the permit above).
@error("blocked by UNTRUSTED_DATA taint")
forbid(
    principal,
    action == Action::"tools/call",
    resource == Resource::"check_untrusted_tool"
) when {
    context.taints.contains("UNTRUSTED_DATA")
};

// remove_taint_tool: allowed, removes UNTRUSTED_DATA taint.
@id("remove_taint:UNTRUSTED_DATA:rule")
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"remove_taint_tool"
);

// allowed_tool: permitted with no taint effects.
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"allowed_tool"
);

// neutral_tool: permitted with no taint effects.
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"neutral_tool"
);
