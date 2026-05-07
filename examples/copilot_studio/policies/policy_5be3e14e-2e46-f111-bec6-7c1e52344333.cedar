// =============================================================================
// Lilith Zero — Copilot Studio Security Policy
// Bot: 5be3e14e-2e46-f111-bec6-7c1e52344333
//
// SECURITY MODEL
// ==============
// Two taints track the session's exposure across tool calls:
//
//   UNTRUSTED_SOURCE — agent retrieved content from an untrusted external
//                      source (web search, arbitrary URL fetch). Content may
//                      have been crafted to manipulate the agent.
//
//   ACCESS_PRIVATE   — agent accessed private organisational data (emails,
//                      documents). This data must not reach untrusted parties.
//
// LETHAL TRIFECTA
// ===============
// When BOTH taints are present the session has the full attack surface for
// data exfiltration: a compromised instruction from the web + access to
// private data. Only TRUSTED NETWORK connections are permitted at this point.
//
//   Trusted network  — recipients/destinations known to be under organisational
//                      control. Always allowed regardless of taint state.
//
//   Untrusted network — everything not on the allowlist. Blocked when both
//                       taints are active.
//
// TRUSTED NETWORK ALLOWLIST (email recipient domains)
// ====================================================
//   @otp.hu          — internal corporate domain
//   @badcompany.xyz  — product team domain
//
//   Add further entries to the lethal_trifecta:email forbid rule below.
//
// TOOL TAINT MAP
// ==============
//   SearchWeb     → UNTRUSTED_SOURCE (web results may be attacker-controlled)
//   ReadEmails    → ACCESS_PRIVATE
//   FetchWebpage  → UNTRUSTED_SOURCE (arbitrary URL content is untrusted)
//   SendEmail     → no taint; trusted recipients always allowed
//   ExecutePython → local execution only; exempt from lethal trifecta
// =============================================================================

// ---------------------------------------------------------------------------
// Resource passthrough — allows tool argument fields (to, url, code, …) to
// be accessible as context.arguments in policy conditions.
// ---------------------------------------------------------------------------
permit(
    principal,
    action in [Action::"resources/read", Action::"resources/write"],
    resource
);

// =============================================================================
// SECTION 1 — Global guardrails (always-on, independent of taint state)
// =============================================================================

// Guard: Block socket-based covert channels and shell execution in Python.
// These patterns can bypass network controls even when the lethal trifecta
// is active, so they are blocked unconditionally.
@id("guardrail:code_injection")
@error("Blocked: Python code contains prohibited patterns (socket / shell execution)")
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"cra65_otpdemo.action.ExecutePython-ExecutePython" ||
     resource == Resource::"cra65_otpdemo.action.ExecutePythonScript-ExecutePythonScript" ||
     resource == Resource::"Execute-Python" ||
     resource == Resource::"Execute-Python-Script") &&
    (context.arguments.code like "*import socket*" ||
     context.arguments.code like "*os.system*")
};

// Guard: Block known-malicious URL patterns in FetchWebpage.
// Belt-and-suspenders check that fires regardless of session taint state.
@id("guardrail:malicious_url")
@error("Blocked: URL matches a known malicious pattern")
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"cra65_otpdemo.action.FetchWebpage-FetchWebpage" ||
     resource == Resource::"Fetch-Webpage") &&
    (context.arguments.url like "*malicious-site.com*" ||
     context.arguments.url like "*exploit*")
};

// =============================================================================
// SECTION 2 — Lethal trifecta rules
// Fires when ACCESS_PRIVATE + UNTRUSTED_SOURCE are both present in the session.
// =============================================================================

// Lethal trifecta — email exfiltration to untrusted recipient.
//
// When both taints are active, outbound email is permitted ONLY to domains on
// the trusted network allowlist. Any other recipient is an untrusted exfiltration
// channel and the send is blocked.
//
// To add a trusted domain: append
//   || context.arguments.to like "*@yourdomain.com"
// inside the negated condition below.
@id("lethal_trifecta:email_untrusted_recipient")
@error("Blocked: sending to an untrusted recipient while session carries both UNTRUSTED_SOURCE and ACCESS_PRIVATE taints")
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"cra65_otpdemo.action.SendEmail-SendEmail" ||
     resource == Resource::"Send-Email") &&
    context.taints.contains("ACCESS_PRIVATE") &&
    context.taints.contains("UNTRUSTED_SOURCE") &&
    !(context.arguments.to like "*@otp.hu" ||
      context.arguments.to like "*@badcompany.xyz")
};

// Lethal trifecta — web exfiltration via FetchWebpage.
//
// Any external HTTP fetch when both taints are active is treated as attempted
// exfiltration. There is no trusted-URL exception: a trusted domain in the URL
// provides no guarantee when the agent is operating under a compromised
// instruction — the URL itself may be attacker-controlled.
@id("lethal_trifecta:fetch_untrusted_url")
@error("Blocked: fetching external content while session carries both UNTRUSTED_SOURCE and ACCESS_PRIVATE taints")
forbid(
    principal,
    action == Action::"tools/call",
    resource
) when {
    (resource == Resource::"cra65_otpdemo.action.FetchWebpage-FetchWebpage" ||
     resource == Resource::"Fetch-Webpage") &&
    context.taints.contains("ACCESS_PRIVATE") &&
    context.taints.contains("UNTRUSTED_SOURCE")
};

// =============================================================================
// SECTION 3 — Tool permits with taint side-effects
// =============================================================================

// SearchWeb — permitted; marks session with UNTRUSTED_SOURCE.
// Web results are external content that may contain attacker-controlled
// instructions. Even a benign query retrieves content from the open web.
@id("add_taint:UNTRUSTED_SOURCE:search_web")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"cra65_otpdemo.action.SearchWeb-SearchWeb" ||
    resource == Resource::"Search-Web"
};

// ReadEmails — permitted; marks session with ACCESS_PRIVATE.
// Email contents are organisational private data. Once read, the lethal
// trifecta rule governs what can be sent where.
@id("add_taint:ACCESS_PRIVATE:read_emails")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"cra65_otpdemo.action.ReadEmails-ReadEmails" ||
    resource == Resource::"Read-Emails"
};

// FetchWebpage — permitted when guardrails pass and lethal trifecta is not
// active; marks session with UNTRUSTED_SOURCE. Once both taints are present
// this tool is blocked by lethal_trifecta:fetch_untrusted_url above.
@id("add_taint:UNTRUSTED_SOURCE:fetch_webpage")
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"cra65_otpdemo.action.FetchWebpage-FetchWebpage" ||
    resource == Resource::"Fetch-Webpage"
};

// SendEmail — permitted unconditionally. Trusted allowlist recipients are
// never blocked because the lethal trifecta forbid condition explicitly
// excludes them via the negated allowlist check. No taint is applied: sending
// email does not introduce new data into the session.
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"cra65_otpdemo.action.SendEmail-SendEmail" ||
    resource == Resource::"Send-Email"
};

// ExecutePython — permitted; exempt from the lethal trifecta.
// Local computation only — not a network exfiltration channel. The code
// injection guardrail in Section 1 handles patterns that could turn it into one.
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
