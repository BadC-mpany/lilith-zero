# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Sentinel, please report it responsibly.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities via one of these methods:

1. **Email**: Send details to [security@example.com] (replace with actual email)
2. **GitHub Security Advisories**: Use the "Security" tab → "Report a vulnerability"

### What to Include

Please include the following in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information for follow-up

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Target**: Within 30 days for critical issues

### Scope

The following are in scope for security reports:

- **Sentinel Interceptor (Rust)**: Authentication bypass, policy bypass, session forgery
- **Sentinel SDK (Python)**: Command injection, insecure defaults
- **Cryptographic Issues**: Weak randomness, timing attacks, signature bypass
- **Process Isolation**: Escape from Job Object/PR_SET_PDEATHSIG

### Out of Scope

- Vulnerabilities in dependencies (report to upstream maintainers)
- Issues requiring physical access to the machine
- Social engineering attacks
- Denial of service via resource exhaustion (unless trivially exploitable)

### Recognition

We appreciate security researchers who help improve Sentinel. With your permission, we will:

- Credit you in the security advisory
- Add you to our CONTRIBUTORS file
- Provide a reference letter upon request

## Security Design

### Trust Model

Sentinel operates on a Zero Trust model:

1. **The LLM/Agent is untrusted** - May be manipulated via prompt injection
2. **The SDK is minimally trusted** - Handles session handshake only
3. **The Interceptor is trusted** - Enforces all security policies
4. **Tool outputs are untrusted** - Wrapped with Spotlighting delimiters

### Cryptographic Primitives

| Purpose | Algorithm |
|---------|-----------|
| Session ID HMAC | HMAC-SHA256 |
| Random generation | `ring::rand::SystemRandom` (Rust) |
| Signature comparison | Constant-time via `hmac::verify_slice` |

### Session Security

- Session IDs are generated per-process instance
- HMAC key is ephemeral (not persisted)
- Session IDs include version prefix for future algorithm upgrades
- Constant-time comparison prevents timing attacks

## Security Hardening Checklist

When deploying Sentinel in production:

- [ ] Run the interceptor in a restricted user account
- [ ] Use `security_level="high"` for maximum protection
- [ ] Review and minimize `ALLOW` rules in policies
- [ ] Enable logging for audit trails
- [ ] Monitor for policy violation patterns
- [ ] Keep dependencies updated
