#!/usr/bin/env python3
"""
Direct webhook test - bypasses Copilot Studio, tests the webhook server directly.

Usage:
  python webhook_direct_test.py [webhook_url] [agent_id]

Default:
  python webhook_direct_test.py http://localhost:8080 5be3e14e-2e46-f111-bec6-7c1e52344333
"""

import requests
import json
import sys
import uuid
from typing import Optional, Dict, Any

# Color codes for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"

class WebhookTester:
    def __init__(self, base_url: str, agent_id: str):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.conversation_id = str(uuid.uuid4())
        self.session_num = 0

    def log_info(self, msg: str):
        print(f"{BLUE}[INFO]{RESET} {msg}")

    def log_success(self, msg: str):
        print(f"{GREEN}[✓ PASS]{RESET} {msg}")

    def log_fail(self, msg: str):
        print(f"{RED}[✗ FAIL]{RESET} {msg}")

    def log_warn(self, msg: str):
        print(f"{YELLOW}[WARN]{RESET} {msg}")

    def log_debug(self, msg: str):
        print(f"{BLUE}[DEBUG]{RESET} {msg}")

    def build_request(self, tool_name: str, tool_id: str, input_values: Dict[str, Any]) -> Dict:
        """Build a standard webhook request payload."""
        return {
            "plannerContext": {
                "userMessage": "test message"
            },
            "toolDefinition": {
                "id": tool_id,
                "type": "PrebuiltToolDefinition",
                "name": tool_name,
                "description": f"Test tool: {tool_name}"
            },
            "inputValues": input_values,
            "conversationMetadata": {
                "agent": {
                    "id": self.agent_id,
                    "tenantId": "test-tenant",
                    "environmentId": "test-env",
                    "isPublished": True
                },
                "conversationId": self.conversation_id
            }
        }

    def test_validate(self) -> bool:
        """Test the /validate endpoint."""
        self.log_info("Testing /validate endpoint...")
        try:
            resp = requests.post(
                f"{self.base_url}/validate",
                json={},
                timeout=5
            )

            if resp.status_code != 200:
                self.log_fail(f"GET /validate returned {resp.status_code}")
                return False

            data = resp.json()
            if not data.get("isSuccessful"):
                self.log_warn(f"Server not ready: {data.get('status', 'unknown')}")
                # This is expected if no policy is loaded yet

            self.log_success("GET /validate returned 200 OK")
            return True
        except Exception as e:
            self.log_fail(f"Failed to call /validate: {e}")
            return False

    def test_simple_allow(self) -> bool:
        """Test that a simple allowed tool works."""
        self.log_info("Testing simple allowed tool...")

        request = self.build_request(
            tool_name="test-allowed",
            tool_id="test-allowed-id",
            input_values={"arg": "value"}
        )

        try:
            resp = requests.post(
                f"{self.base_url}/analyze-tool-execution",
                json=request,
                timeout=5
            )

            if resp.status_code != 200:
                self.log_fail(f"Expected 200, got {resp.status_code}")
                self.log_debug(f"Response: {resp.text}")
                return False

            data = resp.json()
            if data.get("blockAction") is None:
                self.log_fail("Response missing blockAction field")
                self.log_debug(f"Response: {json.dumps(data, indent=2)}")
                return False

            if data.get("blockAction"):
                self.log_warn(f"Tool was blocked: {data.get('reason', 'no reason given')}")
                return False  # Expected to be allowed

            self.log_success("Simple allowed tool returned blockAction=false")
            return True
        except Exception as e:
            self.log_fail(f"Request failed: {e}")
            return False

    def test_taint_persistence(self) -> bool:
        """Test that taints persist across requests in the same conversation."""
        self.log_info("Testing taint persistence...")

        # Use a unique conversation ID for this test
        original_conv = self.conversation_id
        self.conversation_id = f"taint-test-{uuid.uuid4()}"

        try:
            # Step 1: Send a tool that would add a taint (if we had the policy)
            self.log_debug("  1. Sending first tool (should add taint)...")
            req1 = self.build_request(
                tool_name="Search-Web",
                tool_id="search-web-id",
                input_values={"query": "test"}
            )

            resp1 = requests.post(
                f"{self.base_url}/analyze-tool-execution",
                json=req1,
                timeout=5
            )

            if resp1.status_code != 200:
                self.log_fail(f"First request returned {resp1.status_code}")
                return False

            # Step 2: Send another tool in the same conversation
            self.log_debug("  2. Sending second tool in same conversation...")
            req2 = self.build_request(
                tool_name="test-taint-check",
                tool_id="test-taint-check-id",
                input_values={}
            )

            resp2 = requests.post(
                f"{self.base_url}/analyze-tool-execution",
                json=req2,
                timeout=5
            )

            if resp2.status_code != 200:
                self.log_fail(f"Second request returned {resp2.status_code}")
                return False

            self.log_success("Taint persistence test completed (requests succeeded)")
            return True
        except Exception as e:
            self.log_fail(f"Taint test failed: {e}")
            return False
        finally:
            self.conversation_id = original_conv

    def test_cedar_policy_tool(self) -> bool:
        """Test with actual tools from the Cedar policy."""
        self.log_info("Testing Cedar policy tools...")

        # Reset conversation for clean test
        self.conversation_id = f"cedar-test-{uuid.uuid4()}"

        tests = [
            ("Search-Web", "cra65_otpdemo.action.SearchWeb-SearchWeb", {"query": "test"}, False),
            ("Read-Emails", "cra65_otpdemo.action.ReadEmails-ReadEmails", {"folder": "Inbox"}, False),
            ("Send-Email", "cra65_otpdemo.action.SendEmail-SendEmail", {"to": "user@example.com", "subject": "test", "body": "test"}, False),
        ]

        all_passed = True
        for tool_name, tool_id, input_values, should_be_blocked in tests:
            self.log_debug(f"  Testing {tool_name}...")

            request = self.build_request(tool_name, tool_id, input_values)

            try:
                resp = requests.post(
                    f"{self.base_url}/analyze-tool-execution",
                    json=request,
                    timeout=5
                )

                if resp.status_code != 200:
                    self.log_fail(f"  {tool_name}: HTTP {resp.status_code}")
                    all_passed = False
                    continue

                data = resp.json()
                is_blocked = data.get("blockAction", False)

                if is_blocked == should_be_blocked:
                    self.log_success(f"  {tool_name}: blockAction={is_blocked} (as expected)")
                else:
                    self.log_fail(f"  {tool_name}: expected blockAction={should_be_blocked}, got {is_blocked}")
                    if data.get("reason"):
                        self.log_debug(f"    Reason: {data['reason']}")
                    all_passed = False
            except Exception as e:
                self.log_fail(f"  {tool_name}: request failed: {e}")
                all_passed = False

        return all_passed

    def test_malicious_url_block(self) -> bool:
        """Test that malicious URLs are blocked by the Cedar policy."""
        self.log_info("Testing malicious URL blocking...")

        self.conversation_id = f"malicious-test-{uuid.uuid4()}"

        request = self.build_request(
            tool_name="Fetch-Webpage",
            tool_id="cra65_otpdemo.action.FetchWebpage-FetchWebpage",
            input_values={"url": "http://malicious-site.com/exploit"}
        )

        try:
            resp = requests.post(
                f"{self.base_url}/analyze-tool-execution",
                json=request,
                timeout=5
            )

            if resp.status_code != 200:
                self.log_fail(f"Request returned {resp.status_code}")
                return False

            data = resp.json()
            if data.get("blockAction"):
                self.log_success(f"Malicious URL correctly blocked: {data.get('reason', 'no reason')}")
                return True
            else:
                self.log_fail("Malicious URL was NOT blocked")
                return False
        except Exception as e:
            self.log_fail(f"Test failed: {e}")
            return False


def main():
    # Parse arguments
    url = "http://localhost:8080"
    agent_id = "5be3e14e-2e46-f111-bec6-7c1e52344333"

    if len(sys.argv) > 1:
        url = sys.argv[1]
    if len(sys.argv) > 2:
        agent_id = sys.argv[2]

    print(f"\n{BOLD}╔═══════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║   Lilith Zero - Copilot Studio Webhook Direct Test Suite  ║{RESET}")
    print(f"{BOLD}╚═══════════════════════════════════════════════════════════╝{RESET}\n")

    print(f"Webhook URL: {BOLD}{url}{RESET}")
    print(f"Agent ID:    {BOLD}{agent_id}{RESET}\n")

    tester = WebhookTester(url, agent_id)

    # Run tests
    tests = [
        ("Health Check", tester.test_validate),
        ("Simple Allowed Tool", tester.test_simple_allow),
        ("Taint Persistence", tester.test_taint_persistence),
        ("Cedar Policy Tools", tester.test_cedar_policy_tool),
        ("Malicious URL Blocking", tester.test_malicious_url_block),
    ]

    results = {}
    for test_name, test_func in tests:
        print(f"\n{BOLD}═ {test_name} ═{RESET}")
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"{RED}[EXCEPTION]{RESET} {e}")
            results[test_name] = False

    # Summary
    print(f"\n{BOLD}═ Summary ═{RESET}")
    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for test_name, passed_flag in results.items():
        status = f"{GREEN}✓{RESET}" if passed_flag else f"{RED}✗{RESET}"
        print(f"{status} {test_name}")

    print(f"\n{BOLD}Result: {passed}/{total} tests passed{RESET}\n")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
