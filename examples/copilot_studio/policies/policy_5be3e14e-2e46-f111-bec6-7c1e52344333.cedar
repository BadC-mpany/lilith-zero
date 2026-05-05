// Automatically generated Cedar policy for Bot: 5be3e14e-2e46-f111-bec6-7c1e52344333
// Hardened version with Vanguard Guardrails and Lethal Trifecta Protection.

// Default permit for resources to allow tool arguments (subject, to, etc.) to pass through.
permit(
    principal,
    action in [Action::"resources/read", Action::"resources/write"],
    resource
);

// --- GLOBAL GUARDRAILS ---

// 1. Block Malicious URLs
@id("guardrail:malicious_url")
@error("Tool call blocked: contains malicious URL pattern")
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    context.arguments.url like "*malicious-site.com*" ||
    context.arguments.url like "*exploit*"
};

// 2. Block Code Injection (socket usage)
@id("guardrail:code_injection")
@error("Tool call blocked: prohibited library usage")
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    context.arguments.code like "*import socket*" ||
    context.arguments.code like "*os.system*"
};

// 3. Lethal Trifecta: Block Exfiltration if session is tainted with BOTH Private Data and Untrusted Source
@id("guardrail:lethal_trifecta")
@error("Blocked by lethal trifecta protection: preventing exfiltration of private data accessed from an untrusted source")
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    context.taints.contains("ACCESS_PRIVATE") &&
    context.taints.contains("UNTRUSTED_SOURCE") &&
    (resource == Resource::"Send-Email" ||
     resource == Resource::"SendEmail" ||
     resource == Resource::"cra65_otpdemo.action.SendEmail-SendEmail" ||
     resource == Resource::"Execute-Python" ||
     resource == Resource::"Execute-Python-Script" ||
     resource == Resource::"ExecutePython" ||
     resource == Resource::"ExecutePythonScript" ||
     resource == Resource::"cra65_otpdemo.action.ExecutePython-ExecutePython" ||
     resource == Resource::"cra65_otpdemo.action.ExecutePythonScript-ExecutePythonScript" ||
     resource == Resource::"Fetch-Webpage" ||
     resource == Resource::"FetchWebpage" ||
     resource == Resource::"cra65_otpdemo.action.FetchWebpage-FetchWebpage")
};

// --- TOOL PERMITS ---

// Tool: Search Web
@id("add_taint:UNTRUSTED_SOURCE:search")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"cra65_otpdemo.action.SearchWeb-SearchWeb" ||
    resource == Resource::"Search-Web"
};

// Tool: Read Emails
@id("add_taint:ACCESS_PRIVATE:email")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"cra65_otpdemo.action.ReadEmails-ReadEmails" ||
    resource == Resource::"Read-Emails"
};

// Tool: Fetch Webpage
@id("add_taint:UNTRUSTED_SOURCE:web")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"cra65_otpdemo.action.FetchWebpage-FetchWebpage" ||
    resource == Resource::"Fetch-Webpage"
};

// Tool: Send Email - Block attacker email explicitly
@id("forbid:send_email_to_attacker")
@error("Tool call blocked: cannot send email to attacker@evil.com")
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"cra65_otpdemo.action.SendEmail-SendEmail" ||
     resource == Resource::"Send-Email") &&
    context.arguments.to == "attacker@evil.com"
};

// Tool: Send Email - Permit all other cases
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"cra65_otpdemo.action.SendEmail-SendEmail" ||
    resource == Resource::"Send-Email"
};

// Tool: Execute Python
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"cra65_otpdemo.action.ExecutePython-ExecutePython" ||
    resource == Resource::"cra65_otpdemo.action.ExecutePythonScript-ExecutePythonScript" ||
    resource == Resource::"Execute-Python" ||
    resource == Resource::"Execute-Python-Script"
};
