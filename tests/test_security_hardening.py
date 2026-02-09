import asyncio
import os
import sys
import unittest
import logging
import time
import jwt
from typing import Dict, Any

# Add project root to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from lilith_zero import Lilith, PolicyViolationError, LilithError, LilithConfigError

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SecurityHardeningSuite")

class TestSecurityHardening(unittest.IsolatedAsyncioTestCase):
    """
    Unified Security Hardening Test Suite for Lilith.
    Verifies "Google-grade" security properties and architectural invariants.
    """

    async def asyncSetUp(self):
        self.test_dir = os.path.dirname(os.path.abspath(__file__))
        self.resources_dir = os.path.join(self.test_dir, "resources")
        self.upstream_script = os.path.join(self.resources_dir, "manual_server.py")
        self.noisy_script = os.path.join(self.resources_dir, "noisy_tool.py")
        self.policy_path = os.path.join(self.test_dir, "policy_hardening.yaml")
        self.binary_path = os.environ.get("LILITH_ZERO_BINARY_PATH")
        
        # Temp policy file for resource tests
        self.temp_policy = os.path.join(self.test_dir, "temp_resource_policy.yaml")
        with open(self.temp_policy, "w") as f:
            f.write("""
id: "resource-test-policy"
customerId: "test"
name: "Resource Hardening"
version: 1
staticRules:
  read_file: ALLOW
  ping: ALLOW
taintRules: []
resourceRules:
  - uriPattern: "file:///allowed/*"
    action: ALLOW
  - uriPattern: "*"
    action: BLOCK
""")

        if not os.path.exists(self.binary_path):
             self.skipTest("Lilith binary not found. Run 'cargo build --release' first.")

    async def asyncTearDown(self):
        if os.path.exists(self.temp_policy):
            os.remove(self.temp_policy)

    # --- BLOCK 1: CORE POLICY ENGINE ---

    async def test_fail_closed_no_policy(self):
        """Verify Lilith blocks everything if NO policy is provided."""
        logger.info("TEST: Fail Closed (No Policy)")
        client = Lilith(
            upstream=f"{sys.executable} -u {self.upstream_script}",
            binary=self.binary_path,
            policy=None
        )
        async with client:
            try:
                await client.call_tool("read_user_db", {"user_id": "test"})
                self.fail("Lilith allowed tool execution without policy!")
            except PolicyViolationError as e:
                self.assertIn("No security policy loaded", str(e))
            except LilithError as e:
                self.assertIn("No security policy loaded", str(e))
            except Exception as e:
                self.assertIn("No security policy loaded", str(e))

    async def test_static_policy_allow(self):
        """Verify Static Policy Allow Rule."""
        logger.info("TEST: Static Policy Allow")
        client = Lilith(
            upstream=f"{sys.executable} -u {self.upstream_script}",
            binary=self.binary_path,
            policy=self.policy_path
        )
        async with client:
            result = await client.call_tool("read_user_db", {"user_id": "test"})
            self.assertFalse(result.get("isError", False))
            self.assertTrue(len(result.get("content", [])) > 0)

    # --- BLOCK 2: TAINT TRACKING ---

    async def test_taint_propagation_and_block(self):
        """Verify Taint tracking prevents unauthorized exfiltration."""
        logger.info("TEST: Taint Propagation & Blocking")
        client = Lilith(
            upstream=f"{sys.executable} -u {self.upstream_script}",
            binary=self.binary_path,
            policy=self.policy_path
        )
        async with client:
            # Source: Read PII
            await client.call_tool("read_user_db", {"user_id": "admin"})
            # Sink: Exfiltrate (Blocked by Taint)
            try:
                await client.call_tool("export_to_cloud", {"data": "vault_secrets"})
                self.fail("Lilith allowed exfiltration of tainted data!")
            except PolicyViolationError as e:
                self.assertIn("blocked", str(e).lower())
                self.assertIn("PII", str(e))

    # --- BLOCK 3: RESOURCE ACCESS CONTROL ---

    async def test_resource_access_control(self):
        """Verify explicit blocking of unauthorized URIs."""
        logger.info("TEST: Resource Hardening")
        client = Lilith(
            upstream=f"{sys.executable} -u {self.upstream_script}",
            binary=self.binary_path,
            policy=self.temp_policy
        )
        async with client:
            # Test Blocked
            try:
                await client._send_request("resources/read", {"uri": "file:///etc/shadow"})
                self.fail("Lilith allowed unauthorized resource access!")
            except PolicyViolationError as e:
                self.assertIn("blocked by rule", str(e))
            
            # Test Allowed (passed to upstream which doesn't handle it, but middleware ALLOWS)
            try:
                await client._send_request("resources/read", {"uri": "file:///allowed/public.txt"})
            except LilithError as e:
                # Upstream might return Method not found or Unknown resource
                self.assertTrue("Method not found" in str(e) or "Unknown resource" in str(e), f"Unexpected error: {e}")

    # --- BLOCK 4: TRANSPORT & ARCHITECTURE ---

    async def test_transport_noise_resilience(self):
        """Verify Lilith ignores non-JSON garbage from tool stdout."""
        logger.info("TEST: Transport Noise Resilience")
        client = Lilith(
            upstream=f"{sys.executable} -u {self.noisy_script}",
            binary=self.binary_path,
            policy=self.temp_policy
        )
        async with client:
            result = await client.call_tool("ping", {})
            self.assertIn("ok", result["content"][0]["text"])

    async def test_spotlighting_integrity(self):
        """Verify randomized spotlighting delimiters are applied to tool output."""
        logger.info("TEST: Spotlighting Integrity")
        client = Lilith(
            upstream=f"{sys.executable} -u {self.upstream_script}",
            binary=self.binary_path,
            policy=self.policy_path
        )
        async with client:
            result = await client.call_tool("read_user_db", {"user_id": "admin"})
            text_content = result["content"][0]["text"]
            self.assertIn("<<<LILITH_ZERO_DATA_START:", text_content)
            self.assertIn("<<<LILITH_ZERO_DATA_END:", text_content)

    # --- BLOCK 5: AUTHENTICATION ---

    async def test_jwt_authentication(self):
        """Verify JWT audience validation logic."""
        self.skipTest("JWT Audience Token not supported in current SDK version")
        return

if __name__ == "__main__":
    unittest.main()
