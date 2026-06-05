// Resource passthrough — allows resource read/write actions to be evaluated
permit(
    principal,
    action in [Action::"resources/read", Action::"resources/write"],
    resource
);

// Allow read_file tool calls
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"read_file"
);

// Forbid Execute-Python tool calls
forbid(
    principal,
    action == Action::"tools/call",
    resource == Resource::"Execute-Python"
);
