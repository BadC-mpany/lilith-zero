#!/usr/bin/env python3
"""
Azure End-to-End Test Suite for Lilith Zero Webhook

Tests realistic Copilot Studio payloads against Azure deployment.
Validates allow/deny logic, taint persistence, and session isolation.

Usage:
  python azure_e2e_test.py [webhook_url] [agent_id]

Default:
  python azure_e2e_test.py https://lilith-zero.badcompany.xyz 5be3e14e-2e46-f111-bec6-7c1e52344333
"""

import requests
import json
import sys
import uuid
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

# Color codes for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

@dataclass
class TestCase:
    name: str
    phase: str
    expected_block: bool
    passed: bool = False
    actual_block: Optional[bool] = None
    reason: Optional[str] = None
    error: Optional[str] = None

class AzureE2ETester:
    def __init__(self, base_url: str, agent_id: str):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.results: List[TestCase] = []
        self.conversation_counter = 0

    def new_conversation_id(self) -> str:
        """Generate unique conversation ID for test isolation."""
        self.conversation_counter += 1
        return f"test-{self.conversation_counter}-{uuid.uuid4().hex[:8]}"

    def build_payload(
        self,
        tool_id: str,
        tool_name: str,
        input_values: Dict[str, Any],
        conversation_id: str
    ) -> Dict:
        """Build realistic Copilot Studio webhook payload."""
        return {
            "plannerContext": {
                "userMessage": f"Testing {tool_name}",
                "thought": "Lilith Zero security validation",
                "chatHistory": [],
                "previousToolsOutputs": []
            },
            "toolDefinition": {
                "id": tool_id,
                "type": "ToolDefinition",
                "name": tool_name,
                "description": f"Test tool: {tool_name}",
                "inputParameters": [],
                "outputParameters": []
            },
            "inputValues": input_values,
            "conversationMetadata": {
                "agent": {
                    "id": self.agent_id,
                    "tenantId": "test-tenant",
                    "environmentId": "test-env",
                    "name": "otp_demo",
                    "isPublished": True
                },
                "conversationId": conversation_id,
                "channelId": "pva-studio"
            }
        }

    def send_request(
        self,
        tool_id: str,
        tool_name: str,
        input_values: Dict[str, Any],
        conversation_id: str,
        phase: str,
        expected_block: bool,
        debug: bool = False
    ) -> TestCase:
        """Send webhook request and record result."""
        payload = self.build_payload(tool_id, tool_name, input_values, conversation_id)

        test = TestCase(
            name=tool_name,
            phase=phase,
            expected_block=expected_block
        )

        try:
            response = requests.post(
                f"{self.base_url}/analyze-tool-execution",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if response.status_code != 200:
                test.error = f"HTTP {response.status_code}: {response.text[:100]}"
                return test

            result = response.json()
            actual_block = result.get("blockAction", False)
            test.actual_block = actual_block
            test.reason = result.get("reason", "")
            test.passed = (actual_block == expected_block)

            if debug:
                print(f"     DEBUG: Full response: {json.dumps(result, indent=6)}")

        except requests.Timeout:
            test.error = "Request timeout (10s)"
        except requests.ConnectionError as e:
            test.error = f"Connection error: {str(e)[:100]}"
        except Exception as e:
            test.error = f"Error: {str(e)[:100]}"

        self.results.append(test)
        return test

    def print_result(self, test: TestCase, conversation_id: str = ""):
        """Print individual test result in nextest style."""
        if test.error:
            print(f"{RED}FAIL{RESET} {test.phase} :: {test.name}")
            print(f"     ERROR: {test.error}")
            return

        if test.passed:
            print(f"{GREEN}✓{RESET} {test.phase} :: {test.name}")
        else:
            print(f"{RED}FAIL{RESET} {test.phase} :: {test.name}")
            print(f"     Expected: blockAction={test.expected_block}, Got: blockAction={test.actual_block}")
            if test.reason:
                print(f"     Reason: {test.reason}")
            print(f"     Conv: {conversation_id}")

    def print_summary(self):
        """Print nextest-style summary."""
        passed = sum(1 for t in self.results if t.passed and not t.error)
        failed = sum(1 for t in self.results if (not t.passed or t.error))
        total = len(self.results)

        print(f"\n{BOLD}{'='*70}{RESET}")
        print(f"{BOLD}RESULTS{RESET}")
        print(f"{BOLD}{'='*70}{RESET}")

        if failed == 0:
            print(f"{GREEN}{BOLD}{passed} PASSED{RESET} in {BOLD}{total} test(s){RESET}")
        else:
            print(f"{RED}{BOLD}{passed} PASSED{RESET}, {RED}{BOLD}{failed} FAILED{RESET} in {BOLD}{total} test(s){RESET}")

    def run_phase_1_basic_allow_deny(self):
        """Phase 1: Basic allow/deny without taints."""
        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}PHASE 1: Basic Allow/Deny (No Taints){RESET}")
        print(f"{CYAN}{'='*70}{RESET}")

        conv = self.new_conversation_id()

        # Allowed tool
        self.send_request(
            tool_id="cra65_otpdemo.action.SearchWeb-SearchWeb",
            tool_name="Search-Web (allowed)",
            input_values={"query": "test"},
            conversation_id=conv,
            phase="P1",
            expected_block=False
        )
        self.print_result(self.results[-1], conv)

        # Allowed tool
        self.send_request(
            tool_id="cra65_otpdemo.action.ReadEmails-ReadEmails",
            tool_name="Read-Emails (allowed)",
            input_values={"folder": "Inbox"},
            conversation_id=conv,
            phase="P1",
            expected_block=False
        )
        self.print_result(self.results[-1], conv)

        # Send-Email without taints should be ALLOWED
        self.send_request(
            tool_id="cra65_otpdemo.action.SendEmail-SendEmail",
            tool_name="Send-Email (no taints, should allow)",
            input_values={"to": "user@example.com"},
            conversation_id=conv,
            phase="P1",
            expected_block=False
        )
        self.print_result(self.results[-1], conv)

    def run_phase_2_taint_accumulation(self):
        """Phase 2: Taint accumulation across requests in same conversation."""
        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}PHASE 2: Taint Accumulation (Same Conversation){RESET}")
        print(f"{CYAN}Proof that taints persist and block tools across requests{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")

        conv = self.new_conversation_id()

        # Request 1: Search-Web adds UNTRUSTED_SOURCE
        print(f"\n{YELLOW}[STEP 1/4]{RESET} Search-Web (adds UNTRUSTED_SOURCE)")
        self.send_request(
            tool_id="cra65_otpdemo.action.SearchWeb-SearchWeb",
            tool_name="Search-Web (adds UNTRUSTED_SOURCE)",
            input_values={"query": "untrusted data from web"},
            conversation_id=conv,
            phase="P2-S1",
            expected_block=False
        )
        self.print_result(self.results[-1], conv)

        # Request 2: Read-Emails adds ACCESS_PRIVATE
        print(f"\n{YELLOW}[STEP 2/4]{RESET} Read-Emails (adds ACCESS_PRIVATE)")
        self.send_request(
            tool_id="cra65_otpdemo.action.ReadEmails-ReadEmails",
            tool_name="Read-Emails (adds ACCESS_PRIVATE)",
            input_values={"folder": "Inbox"},
            conversation_id=conv,
            phase="P2-S2",
            expected_block=False
        )
        self.print_result(self.results[-1], conv)

        # Request 3: Send-Email should now be BLOCKED (lethal trifecta)
        print(f"\n{YELLOW}[STEP 3/4]{RESET} Send-Email (both taints present - LETHAL TRIFECTA)")
        self.send_request(
            tool_id="cra65_otpdemo.action.SendEmail-SendEmail",
            tool_name="Send-Email (both taints present, SHOULD BLOCK)",
            input_values={"to": "recipient@company.com", "subject": "Data", "body": "Confidential"},
            conversation_id=conv,
            phase="P2-S3",
            expected_block=True,
            debug=True
        )
        self.print_result(self.results[-1], conv)

        # Request 4: Verify taint state persists (another Send-Email should also be blocked)
        print(f"\n{YELLOW}[STEP 4/4]{RESET} Send-Email again (taints should persist)")
        self.send_request(
            tool_id="cra65_otpdemo.action.SendEmail-SendEmail",
            tool_name="Send-Email (again, should still block)",
            input_values={"to": "another@example.com"},
            conversation_id=conv,
            phase="P2-S4",
            expected_block=True
        )
        self.print_result(self.results[-1], conv)

    def run_phase_3_session_isolation(self):
        """Phase 3: Verify sessions are isolated between conversations."""
        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}PHASE 3: Session Isolation (Different Conversations){RESET}")
        print(f"{CYAN}Proof that taints don't cross conversation boundaries{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")

        # Conversation A: Add taints
        conv_a = self.new_conversation_id()
        print(f"\n{YELLOW}[CONV-A]{RESET} Adding taints...")

        self.send_request(
            tool_id="cra65_otpdemo.action.SearchWeb-SearchWeb",
            tool_name="Search-Web (in Conversation A)",
            input_values={"query": "test"},
            conversation_id=conv_a,
            phase="P3-A1",
            expected_block=False
        )
        self.print_result(self.results[-1], conv_a)

        self.send_request(
            tool_id="cra65_otpdemo.action.ReadEmails-ReadEmails",
            tool_name="Read-Emails (in Conversation A)",
            input_values={"folder": "Inbox"},
            conversation_id=conv_a,
            phase="P3-A2",
            expected_block=False
        )
        self.print_result(self.results[-1], conv_a)

        # Conversation A: Send-Email should be blocked
        self.send_request(
            tool_id="cra65_otpdemo.action.SendEmail-SendEmail",
            tool_name="Send-Email (in Conversation A, should block)",
            input_values={"to": "test@example.com"},
            conversation_id=conv_a,
            phase="P3-A3",
            expected_block=True
        )
        self.print_result(self.results[-1], conv_a)

        # Conversation B: Fresh session, no taints
        conv_b = self.new_conversation_id()
        print(f"\n{YELLOW}[CONV-B]{RESET} Clean session (should allow everything)...")

        # Same Send-Email in fresh conversation should be ALLOWED
        self.send_request(
            tool_id="cra65_otpdemo.action.SendEmail-SendEmail",
            tool_name="Send-Email (in Conversation B, should allow)",
            input_values={"to": "test@example.com"},
            conversation_id=conv_b,
            phase="P3-B1",
            expected_block=False
        )
        self.print_result(self.results[-1], conv_b)

def main():
    # Parse arguments
    base_url = "https://lilith-zero.badcompany.xyz"
    agent_id = "5be3e14e-2e46-f111-bec6-7c1e52344333"

    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    if len(sys.argv) > 2:
        agent_id = sys.argv[2]

    print(f"\n{BOLD}╔════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║  Lilith Zero - Azure E2E Test Suite                   ║{RESET}")
    print(f"{BOLD}║  Taint Persistence & Session Isolation Verification   ║{RESET}")
    print(f"{BOLD}╚════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"Webhook:  {CYAN}{base_url}/analyze-tool-execution{RESET}")
    print(f"Agent ID: {CYAN}{agent_id}{RESET}\n")

    tester = AzureE2ETester(base_url, agent_id)

    try:
        # Run all test phases
        tester.run_phase_1_basic_allow_deny()
        tester.run_phase_2_taint_accumulation()
        tester.run_phase_3_session_isolation()

        # Print summary
        tester.print_summary()

        # Exit with appropriate code
        failed = sum(1 for t in tester.results if (not t.passed or t.error))
        return 0 if failed == 0 else 1

    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted{RESET}")
        return 1
    except Exception as e:
        print(f"\n{RED}Fatal error: {e}{RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
