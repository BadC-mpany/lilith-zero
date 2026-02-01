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
from sentinel_sdk import SentinelClient as Sentinel

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SecurityHardeningSuite")

class TestSecurityHardening(unittest.IsolatedAsyncioTestCase):
    """
    Unified Security Hardening Test Suite for Sentinel.
    Verifies "Google-grade" security properties and architectural invariants.
    """

    async def asyncSetUp(self):
        self.test_dir = os.path.dirname(os.path.abspath(__file__))
        self.resources_dir = os.path.join(self.test_dir, "resources")
        self.upstream_script = os.path.join(self.resources_dir, "vulnerable_tools.py")
        self.noisy_script = os.path.join(self.resources_dir, "noisy_tool.py")
        self.policy_path = os.path.join(self.test_dir, "policy_hardening.yaml")
        self.binary_path = os.path.abspath("./sentinel/target/release/sentinel.exe")
        
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
             self.skipTest("Sentinel binary not found. Run 'cargo build --release' first.")

    async def asyncTearDown(self):
        if os.path.exists(self.temp_policy):
            os.remove(self.temp_policy)

    # --- BLOCK 1: CORE POLICY ENGINE ---

    async def test_fail_closed_no_policy(self):
        """Verify Sentinel blocks everything if NO policy is provided."""
        logger.info("TEST: Fail Closed (No Policy)")
        client = Sentinel(
            upstream_cmd=sys.executable,
            upstream_args=["-u", self.upstream_script],
            binary_path=self.binary_path,
            policy_path=None
        )
        async with client:
            try:
                await client.execute_tool("read_user_db", {"user_id": "test"})
                self.fail("Sentinel allowed tool execution without policy!")
            except Exception as e:
                self.assertIn("No security policy loaded", str(e))

    async def test_static_policy_allow(self):
        """Verify Static Policy Allow Rule."""
        logger.info("TEST: Static Policy Allow")
        client = Sentinel(
            upstream_cmd=sys.executable,
            upstream_args=["-u", self.upstream_script],
            binary_path=self.binary_path,
            policy_path=self.policy_path
        )
        async with client:
            result = await client.execute_tool("read_user_db", {"user_id": "test"})
            self.assertFalse(result.get("isError", False))
            self.assertTrue(len(result.get("content", [])) > 0)

    # --- BLOCK 2: TAINT TRACKING ---

    async def test_taint_propagation_and_block(self):
        """Verify Taint tracking prevents unauthorized exfiltration."""
        logger.info("TEST: Taint Propagation & Blocking")
        client = Sentinel(
            upstream_cmd=sys.executable,
            upstream_args=["-u", self.upstream_script],
            binary_path=self.binary_path,
            policy_path=self.policy_path
        )
        async with client:
            # Source: Read PII
            await client.execute_tool("read_user_db", {"user_id": "admin"})
            # Sink: Exfiltrate (Blocked by Taint)
            try:
                await client.execute_tool("export_to_cloud", {"data": "vault_secrets"})
                self.fail("Sentinel allowed exfiltration of tainted data!")
            except Exception as e:
                self.assertIn("BLOCKED", str(e))
                self.assertIn("PII", str(e))

    # --- BLOCK 3: RESOURCE ACCESS CONTROL ---

    async def test_resource_access_control(self):
        """Verify explicit blocking of unauthorized URIs."""
        logger.info("TEST: Resource Hardening")
        client = Sentinel(
            upstream_cmd=sys.executable,
            upstream_args=["-u", self.upstream_script],
            binary_path=self.binary_path,
            policy_path=self.temp_policy
        )
        async with client:
            # Test Blocked
            try:
                await client._send_request("resources/read", {"uri": "file:///etc/shadow"})
                self.fail("Sentinel allowed unauthorized resource access!")
            except Exception as e:
                self.assertIn("blocked by rule", str(e))
            
            # Test Allowed (passed to upstream which doesn't handle it, but middleware ALLOWS)
            try:
                await client._send_request("resources/read", {"uri": "file:///allowed/public.txt"})
            except Exception as e:
                # Upstream might return Method not found or Unknown resource, which proves it passed the middleware
                self.assertTrue("Method not found" in str(e) or "Unknown resource" in str(e), f"Unexpected error: {e}")

    # --- BLOCK 4: TRANSPORT & ARCHITECTURE ---

    async def test_transport_noise_resilience(self):
        """Verify Sentinel ignores non-JSON garbage from tool stdout."""
        logger.info("TEST: Transport Noise Resilience")
        client = Sentinel(
            upstream_cmd=sys.executable,
            upstream_args=["-u", self.noisy_script],
            binary_path=self.binary_path,
            policy_path=self.temp_policy
        )
        async with client:
            result = await client.execute_tool("ping", {})
            self.assertIn("ok", result["content"][0]["text"])

    async def test_spotlighting_integrity(self):
        """Verify randomized spotlighting delimiters are applied to tool output."""
        logger.info("TEST: Spotlighting Integrity")
        client = Sentinel(
            upstream_cmd=sys.executable,
            upstream_args=["-u", self.upstream_script],
            binary_path=self.binary_path,
            policy_path=self.policy_path
        )
        async with client:
            result = await client.execute_tool("read_user_db", {"user_id": "admin"})
            text_content = result["content"][0]["text"]
            self.assertIn("<<<SENTINEL_DATA_START:", text_content)
            self.assertIn("<<<SENTINEL_DATA_END:", text_content)

    # --- BLOCK 5: AUTHENTICATION ---

    async def test_jwt_authentication(self):
        """Verify JWT audience validation logic."""
        logger.info("TEST: JWT Authentication")
        secret = "test_secret_key"
        os.environ["SENTINEL_JWT_SECRET"] = secret
        os.environ["SENTINEL_EXPECTED_AUDIENCE"] = "https://verified.api"
        
        # Valid Token
        valid_token = jwt.encode({
            "aud": "https://verified.api",
            "exp": int(time.time() + 60)
        }, secret, algorithm="HS256")

        # Invalid Token (Wrong Signature)
        invalid_token = jwt.encode({"aud": "https://verified.api"}, "evil_key", algorithm="HS256")

        try:
            # 1. Test success
            client = Sentinel(
                upstream_cmd=sys.executable,
                upstream_args=["-u", self.upstream_script],
                binary_path=self.binary_path,
                policy_path=self.policy_path,
                audience_token=valid_token
            )
            async with client:
                await client.execute_tool("ping", {})

            # 2. Test fail
            client_fail = Sentinel(
                upstream_cmd=sys.executable,
                upstream_args=["-u", self.upstream_script],
                binary_path=self.binary_path,
                policy_path=self.policy_path,
                audience_token=invalid_token
            )
            try:
                async with client_fail:
                    await client_fail.execute_tool("ping", {})
                self.fail("Sentinel accepted invalid JWT!")
            except Exception as e:
                self.assertIn("Audience validation failed", str(e))

        finally:
            del os.environ["SENTINEL_JWT_SECRET"]
            del os.environ["SENTINEL_EXPECTED_AUDIENCE"]

if __name__ == "__main__":
    unittest.main()
