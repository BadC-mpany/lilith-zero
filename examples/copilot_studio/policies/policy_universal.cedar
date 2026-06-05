// =============================================================================
// Lilith Zero — Universal Security Policy (Cedar Native)
// =============================================================================

// Permit resource access checks by default (read)
permit(
    principal,
    action == Action::"resources/read",
    resource
);

// Permit resource access checks by default (write)
permit(
    principal,
    action == Action::"resources/write",
    resource
);

// Permit tool execution by default (unless explicitly forbidden below)
@id("default_allow_tools")
permit(
    principal,
    action == Action::"tools/call",
    resource
);

// Static deny rule for delete_file
@id("static_deny:delete_file")
forbid(
    principal,
    action == Action::"tools/call",
    resource == Resource::"delete_file"
);

// =============================================================================
// SECTION 1 — Always-on Guardrails
// =============================================================================

// Guardrail: Block known-malicious Python code injection patterns
@id("guardrail:python_injection")
forbid(
    principal,
    action == Action::"tools/call",
    resource == Resource::"Execute-Python"
) when {
    context.args.code like "*import socket*" ||
    context.args.code like "*os.system*" ||
    context.args.code like "*subprocess*" ||
    context.args.code like "*__import__*"
};

// Guardrail: Block malicious URL patterns in FetchWebpage
@id("guardrail:malicious_url")
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"fetch_webpage" || resource == Resource::"web_fetch") &&
    (context.args.url like "*malicious-site.com*" ||
     context.args.url like "*exploit*" ||
     context.args.url like "*malware*")
};

// Guardrail: Block SQL Injection patterns in database queries
@id("guardrail:sql_injection")
forbid(
    principal,
    action == Action::"tools/call",
    resource == Resource::"query_sql"
) when {
    context.args.query like "*--*" ||
    context.args.query like "* UNION *" ||
    context.args.query like "* OR 1=1*"
};

// Guardrail: Block system directory traversals on write_file
@id("guardrail:system_path_write")
forbid(
    principal,
    action == Action::"tools/call",
    resource == Resource::"write_file"
) when {
    context.args.path like "/etc/*" ||
    context.args.path like "/usr/*" ||
    context.args.path like "/bin/*"
};

// =============================================================================
// SECTION 2 — Taint Tracking Rules
// =============================================================================

// Taint: Mark session with SECRET when reading env/config files
@id("add_taint:SECRET:read_sensitive_file")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"read_file" || resource == Resource::"readFile") &&
    (context.args.path like "*infra/*.env" || context.args.path like "*config/manifest.json")
};

// Taint: Mark session with SECRET when querying db schema/secrets
@id("add_taint:SECRET:query_sensitive_db")
permit(
    principal,
    action == Action::"tools/call",
    resource == Resource::"query_sql"
) when {
    context.args.query like "*secrets*" ||
    context.args.query like "*credentials*"
};

// Taint: Mark session with PII when reading CSV data
@id("add_taint:PII:read_pii_csv")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"read_file" || resource == Resource::"readFile") &&
    (context.args.path like "*data/*.csv" || context.args.path like "*customers.csv")
};

// Taint: Mark session with UNTRUSTED when reading external or compliance docs
@id("add_taint:UNTRUSTED:read_untrusted_doc")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"read_file" || resource == Resource::"readFile") &&
    (context.args.path like "*docs/compliance/*" || context.args.path like "*vendor/*")
};

// Taint: Mark session with UNTRUSTED when searching the web
@id("add_taint:UNTRUSTED:web_search")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"WebSearch" || resource == Resource::"web_search"
};

// =============================================================================
// SECTION 3 — Lethal Trifecta (Sensitive Data + Untrusted Source)
// =============================================================================

// Lethal Trifecta: Block web exfiltration of SECRETS combined with UNTRUSTED sources
@id("lethal_trifecta:secrets_exfil")
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"fetch_webpage" || resource == Resource::"web_fetch") &&
    context.taints.contains("SECRET") &&
    context.taints.contains("UNTRUSTED") &&
    !(context.args.url like "*.badcompany.xyz" || context.args.url like "*.otp.hu")
};

// Lethal Trifecta: Block web exfiltration of PII combined with UNTRUSTED sources
@id("lethal_trifecta:pii_exfil")
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"fetch_webpage" || resource == Resource::"web_fetch") &&
    context.taints.contains("PII") &&
    context.taints.contains("UNTRUSTED") &&
    !(context.args.url like "*.badcompany.xyz" || context.args.url like "*.otp.hu")
};

// Lethal Trifecta: Block terminal/bash downloads/exfiltrations under taint
@id("lethal_trifecta:terminal_exfil")
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"bash" || resource == Resource::"run_in_terminal") &&
    context.taints.contains("UNTRUSTED") &&
    (context.taints.contains("SECRET") || context.taints.contains("PII")) &&
    (context.args.command like "*curl*" || context.args.command like "*wget*" || context.args.command like "*http*")
};
