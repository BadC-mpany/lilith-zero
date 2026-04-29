// Native Cedar Policy for Lilith-Zero
// Demonstrates formal verification and complex logic without YAML limitations.

// 1. Permit all tools by default unless explicitly forbidden
permit(
    principal,
    action == Action::"tools/call",
    resource
);

// 2. Block the "lethal trifecta"
// If the agent has read a secret AND an untrusted source, block exfiltration tools.
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    context.taints.contains("SECRET") &&
    context.taints.contains("UNTRUSTED") &&
    context.classes.contains("EXFILTRATION")
};

// 3. Mandatory Tainting for sensitive files
// If a file in /infra/ or config/ is read, mark the session as having read a SECRET.
// In Lilith, we use policy IDs starting with "add_taint:" to trigger side effects.
@id("add_taint:SECRET:1")
permit(
    principal,
    action == Action::"resources/read",
    resource
) when {
    context.path like "*/infra/*" || context.path like "*/config/*.json"
};

// 4. Block access to the shadow file entirely
forbid(
    principal,
    action == Action::"resources/read",
    resource
) when {
    context.path like "/etc/shadow"
};

// 5. Permit other resource reads
permit(
    principal,
    action == Action::"resources/read",
    resource
);
