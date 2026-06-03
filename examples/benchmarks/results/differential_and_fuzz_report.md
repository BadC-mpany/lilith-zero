# Lilith Zero: Differential and Fuzzing Report

## Performance and Correctness Summary

| Metric | Value | Status |
|---|---|---|
| Differential correctness | 8/8 passed | ✓ PASS |
| Fuzzing safety | 5/5 passed | ✓ PASS |
| Cedar policy rule coverage | 8.33% | ✓ PASS |
| Webhook peak memory (VmHWM) | 10496 KB | Active |
| CLI peak memory (RSS) | 28464 KB | Active |
| Webhook open FDs delta | 0 | ✓ PASS |

## Test Scenarios

### Differential Accuracy (CLI vs Webhook)
| Scenario | CLI Decision | Webhook Decision | Status |
|---|---|---|---|
| Static Allowed Tool | DENY | DENY | PASS |
| Static Denied Tool | DENY | DENY | PASS |
| Taint Rule Match (ADD_TAINT) | DENY | DENY | PASS |
| Exfiltration Block (Lethal Trifecta) | DENY | DENY | PASS |
| Agent-1 Allowed Tool | ALLOW | ALLOW | PASS |
| Agent-1 Denied Tool | DENY | DENY | PASS |
| Agent-2 Allowed Tool | ALLOW | ALLOW | PASS |
| Agent-2 Denied Tool | DENY | DENY | PASS |

### Fuzzing Safety & Robustness
| Fuzzing Scenario | CLI Decision | Webhook Decision | Status |
|---|---|---|---|
| Fuzz: Deeply Nested Object | DENY | DENY | PASS |
| Fuzz: Giant Tool Name Buffer | DENY | ERROR | PASS |
| Fuzz: Null Byte Path Injection | DENY | ERROR | PASS |
| Fuzz: Directory Traversal | DENY | ERROR | PASS |
| Fuzz: Missing Event Name | DENY | ERROR | PASS |

## Cedar Policy Rule Usage

- **add_taint:PII:_5**: NOT USED (To use this rule, create a test scenario targeting it)
- **add_taint:PII:_6**: NOT USED (To use this rule, create a test scenario targeting it)
- **add_taint:SECRET:_1**: NOT USED (To use this rule, create a test scenario targeting it)
- **add_taint:SECRET:_2**: NOT USED (To use this rule, create a test scenario targeting it)
- **add_taint:SECRET:_3**: NOT USED (To use this rule, create a test scenario targeting it)
- **add_taint:SECRET:_4**: NOT USED (To use this rule, create a test scenario targeting it)
- **add_taint:UNTRUSTED_DOC:_10**: NOT USED (To use this rule, create a test scenario targeting it)
- **add_taint:UNTRUSTED_DOC:_7**: NOT USED (To use this rule, create a test scenario targeting it)
- **add_taint:UNTRUSTED_DOC:_8**: NOT USED (To use this rule, create a test scenario targeting it)
- **add_taint:UNTRUSTED_DOC:_9**: NOT USED (To use this rule, create a test scenario targeting it)
- **allow-delete-agent2**: USED
- **allow-read-agent1**: USED
- **default_resource_permit**: NOT USED (To use this rule, create a test scenario targeting it)
- **deny-delete-agent1**: USED
- **deny-read-agent2**: USED
- **rule_0**: NOT USED (To use this rule, create a test scenario targeting it)
- **rule_11**: NOT USED (To use this rule, create a test scenario targeting it)
- **rule_12**: NOT USED (To use this rule, create a test scenario targeting it)
- **rule_13**: NOT USED (To use this rule, create a test scenario targeting it)
- **rule_14**: NOT USED (To use this rule, create a test scenario targeting it)
- **rule_15**: NOT USED (To use this rule, create a test scenario targeting it)
- **rule_16**: NOT USED (To use this rule, create a test scenario targeting it)
- **rule_17**: NOT USED (To use this rule, create a test scenario targeting it)
- **rule_18**: NOT USED (To use this rule, create a test scenario targeting it)
- **rule_19**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_Bash**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_Glob**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_Grep**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_Read**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_WebSearch**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_Write**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_bash**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_create_file**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_delete_file**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_edit_file**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_fetch_webpage**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_glob**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_grep_search**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_ls**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_manage_todo_list**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_readFile**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_read_file**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_rg**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_runCommand**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_run_in_terminal**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_search**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_view**: NOT USED (To use this rule, create a test scenario targeting it)
- **static_web_fetch**: NOT USED (To use this rule, create a test scenario targeting it)
