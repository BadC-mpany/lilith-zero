# Lilith Zero: Differential and Fuzzing Report

## Performance and Correctness Summary

| Metric | Value | Status |
|---|---|---|
| Differential correctness | 20/20 passed | ✓ PASS |
| Fuzzing safety | 5/5 passed | ✓ PASS |
| Cedar policy rule coverage | 100.00% | ✓ PASS |
| Webhook peak memory (VmHWM) | 10920 KB | Active |
| CLI peak memory (RSS) | 28604 KB | Active |
| Webhook open FDs delta | 0 | ✓ PASS |

## Test Scenarios

### Differential Accuracy (CLI vs Webhook)
| Scenario | CLI Decision | Webhook Decision | Status |
|---|---|---|---|
| Static Allowed Tool | ALLOW | ALLOW | PASS |
| Static Denied Tool | DENY | DENY | PASS |
| Guardrail: Python Code Injection Denied | DENY | DENY | PASS |
| Guardrail: Python Code Injection Allowed | ALLOW | ALLOW | PASS |
| Guardrail: Malicious URL Denied | DENY | DENY | PASS |
| Guardrail: SQL Injection Denied | DENY | DENY | PASS |
| Guardrail: System Path Write Denied | DENY | DENY | PASS |
| Taint Rule: SECRET via file | ALLOW | ALLOW | PASS |
| Taint Rule: SECRET via query | ALLOW | ALLOW | PASS |
| Taint Rule: PII via csv | ALLOW | ALLOW | PASS |
| Taint Rule: UNTRUSTED via doc | ALLOW | ALLOW | PASS |
| Taint Rule: UNTRUSTED via web search | ALLOW | ALLOW | PASS |
| Lethal Trifecta: Secrets Web Exfil Denied | DENY | DENY | PASS |
| Lethal Trifecta: Secrets Web Exfil Allowed (Trusted Domain) | DENY | DENY | PASS |
| Lethal Trifecta: PII Web Exfil Denied | DENY | DENY | PASS |
| Lethal Trifecta: Terminal Exfil Denied | DENY | DENY | PASS |
| Agent-1 Allowed Tool | ALLOW | ALLOW | PASS |
| Agent-1 Denied Tool | DENY | DENY | PASS |
| Agent-2 Allowed Tool | ALLOW | ALLOW | PASS |
| Agent-2 Denied Tool | DENY | DENY | PASS |

### Fuzzing Safety & Robustness
| Fuzzing Scenario | CLI Decision | Webhook Decision | Status |
|---|---|---|---|
| Fuzz: Deeply Nested Object | ALLOW | ALLOW | PASS |
| Fuzz: Giant Tool Name Buffer | ALLOW | ALLOW | PASS |
| Fuzz: Null Byte Path Injection | ALLOW | ALLOW | PASS |
| Fuzz: Directory Traversal | ALLOW | ALLOW | PASS |
| Fuzz: Missing Event Name | DENY | ALLOW | PASS |

## Cedar Policy Rule Usage

- **add_taint:PII:read_pii_csv**: USED
- **add_taint:SECRET:query_sensitive_db**: USED
- **add_taint:SECRET:read_sensitive_file**: USED
- **add_taint:UNTRUSTED:read_untrusted_doc**: USED
- **add_taint:UNTRUSTED:web_search**: USED
- **allow-delete-agent2**: USED
- **allow-read-agent1**: USED
- **default_allow_tools**: USED
- **deny-delete-agent1**: USED
- **deny-read-agent2**: USED
- **guardrail:malicious_url**: USED
- **guardrail:python_injection**: USED
- **guardrail:sql_injection**: USED
- **guardrail:system_path_write**: USED
- **lethal_trifecta:pii_exfil**: USED
- **lethal_trifecta:secrets_exfil**: USED
- **lethal_trifecta:terminal_exfil**: USED
- **static_deny:delete_file**: USED
