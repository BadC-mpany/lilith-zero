#!/usr/bin/env python3
"""
Direct Cedar policy validation test.
Tests if the Cedar policy rules are matching correctly.
"""

import sys

print("""
Cedar Policy Diagnostic Test
============================

The issue: Taints are not being added even though Search-Web and Read-Emails are permitted.

Possible causes:
1. Cedar policy rules with @id("add_taint:...") are not being matched
2. The policy file on Azure is different from the local version
3. The entity store in Cedar evaluator is empty (Entities::empty())
4. Policy IDs are not being extracted from Cedar response diagnostics

Next steps:
1. Check if the Cedar policy file on Azure contains the add_taint rules:
   - Policy file: examples/copilot_studio/policies/policy_5be3e14e-2e46-f111-bec6-7c1e52344333.cedar

2. Verify the rules are exactly:
""")

rules = [
    '@id("add_taint:UNTRUSTED_SOURCE:search")',
    '@id("add_taint:ACCESS_PRIVATE:email")',
    '@id("add_taint:UNTRUSTED_SOURCE:web")',
]

for rule in rules:
    print(f"   - {rule}")

print("""
3. Check server logs for any policy parsing errors

4. Verify that the Cedar evaluator is receiving the policy rules
   - Look for: "Successfully loaded Cedar PolicySet"

5. Check if policy IDs are in the Cedar response diagnostics
   - The security_core.rs code at line 391 iterates:
     "for policy_id in response.diagnostics().reason()"
   - If this list is empty, taints won't be extracted

6. Run the local tests to verify persistence works locally:
   cargo test --test webhook_session_persistence_tests --features webhook

Recommendation:
- Add logging to cedar_evaluator.rs line 99 to print the response diagnostics
- This will show if Cedar is actually returning the policy IDs
""")
