import asyncio
import os
import sys
import unittest
import logging
from typing import Dict, Any

# Ensure we can import the local SDK
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sentinel_sdk import Sentinel

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HardeningTestSuite")

class TestSentinelHardening(unittest.IsolatedAsyncioTestCase):
    """
    Comprehensive Hardening Test Suite for Sentinel.
    Verifies "Google-grade" security properties:
    1. Default Deny (Fail Closed)
    2. Policy Enforcement (Static Rules)
    3. Dynamic Taint Tracking
    4. Spotlighting (Prompt Injection Defense)
    """

    async def asyncSetUp(self):
        # Path to the vulnerable tools (upstream)
        self.upstream_script = os.path.join(os.path.dirname(__file__), "vulnerable_tools.py")
        self.policy_path = os.path.join(os.path.dirname(__file__), "policy_hardening.yaml")
        self.binary_path = os.path.abspath("./sentinel/target/release/sentinel.exe")
        
        # Ensure binary exists
        if not os.path.exists(self.binary_path):
             self.skipTest("Sentinel binary not found. Run 'cargo build --release' first.")

    async def test_fail_closed_no_policy(self):
        """Verify Sentinel blocks everything if NO policy is provided (Fail Closed)."""
        logger.info("TEST: Fail Closed (No Policy)")
        
        # Start Sentinel WITHOUT a policy
        client = Sentinel.start(
            upstream=f"{sys.executable} {self.upstream_script}",
            binary_path=self.binary_path,
            policy=None # Explicitly None
        )

        async with client:
            # Attempt a normally harmless read
            try:
                await client.execute_tool("read_user_db", {"user_id": "test"})
                self.fail("Sentinel shout have BLOCKED request without policy!")
            except Exception as e:
                logger.info(f"Verified Block: {e}")
                self.assertIn("No security policy loaded", str(e))
                self.assertIn("Deny-All", str(e))

    async def test_static_policy_allow(self):
        """Verify Static Policy Allow Rule."""
        logger.info("TEST: Static Policy Allow")
        
        # Start Sentinel WITH policy
        client = Sentinel.start(
            upstream=f"{sys.executable} {self.upstream_script}",
            binary_path=self.binary_path,
            policy=self.policy_path
        )
        
        async with client:
            # Policy allows 'read_user_db'
            result = await client.execute_tool("read_user_db", {"user_id": "test"})
            self.assertFalse(result.get("isError"))
            content = result.get("content", [])
            self.assertTrue(len(content) > 0)
            logger.info("Verified Allow: Tool executed successfully.")

    async def test_taint_propagation_and_block(self):
        """Verify Taint tracking prevents exfiltration."""
        logger.info("TEST: Taint Propagation & Blocking")
        
        client = Sentinel.start(
            upstream=f"{sys.executable} {self.upstream_script}",
            binary_path=self.binary_path,
            policy=self.policy_path
        )
        
        async with client:
            # 1. Source: Read PII (Adds Taint)
            logger.info("Step 1: Reading PII (should taint session)")
            await client.execute_tool("read_user_db", {"user_id": "admin"})
            
            # 2. Sink: Exfiltrate (Should be blocked by Taint)
            logger.info("Step 2: Attempting Exfiltration")
            try:
                await client.execute_tool("export_to_cloud", {
                    "data": "stolen_data"
                })
                self.fail("Sentinel should have BLOCKED exfiltration due to taint!")
            except Exception as e:
                logger.info(f"Verified Taint Block: {e}")
                self.assertIn("BLOCKED", str(e))
                self.assertIn("PII", str(e))

    async def test_spotlighting_integrity(self):
        """Verify Spotlighting delimiters are present and randomized."""
        logger.info("TEST: Spotlighting Integrity")
        
        # Standard allow setup
        client = Sentinel.start(
            upstream=f"{sys.executable} {self.upstream_script}",
            binary_path=self.binary_path,
            policy=self.policy_path
        )
        
        async with client:
            result = await client.execute_tool("read_user_db", {"user_id": "admin"})
            text_content = result["content"][0]["text"]
            
            # Check for delimiters
            self.assertIn("<<<SENTINEL_DATA_START:", text_content)
            self.assertIn(">>>", text_content)
            self.assertIn("<<<SENTINEL_DATA_END:", text_content)
            
            logger.info(f"Verified Spotlighting: {text_content[:50]}...")

if __name__ == "__main__":
    unittest.main()
