"""
Sentinel Integration Tests

Tests end-to-end functionality using the Sentinel.start() API.
Binary discovery is automatic via SENTINEL_BINARY_PATH environment variable
or PATH lookup.
"""
import unittest
import asyncio
import os
import sys
import logging

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_sdk import Sentinel, SentinelClient

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("IntegrationTest")

# Test configuration - relative paths
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TEST_DIR)
POLICY_PATH = os.path.join(TEST_DIR, "policy.yaml")
UPSTREAM_SCRIPT = os.path.join(PROJECT_ROOT, "examples", "vulnerable_tools.py")


class TestSentinelIntegration(unittest.TestCase):
    def setUp(self):
        # Verify test files exist
        if not os.path.exists(POLICY_PATH):
            self.fail(f"Policy file not found at {POLICY_PATH}")
        if not os.path.exists(UPSTREAM_SCRIPT):
            self.fail(f"Upstream script not found at {UPSTREAM_SCRIPT}")

    async def run_integration_test(self):
        logger.info("Initializing Sentinel Client...")
        
        # Build upstream command - use -u for unbuffered I/O
        upstream_cmd = f"{sys.executable} -u {UPSTREAM_SCRIPT}"
        
        try:
            client = Sentinel.start(
                upstream=upstream_cmd,
                policy=POLICY_PATH,
                security_level="high"
            )
        except FileNotFoundError as e:
            self.fail(
                f"Sentinel binary not found: {e}. "
                f"Set SENTINEL_BINARY_PATH environment variable."
            )
        
        async with client:
            logger.info(f"Session Started: {client.session_id}")
            self.assertIsNotNone(client.session_id, "Session ID should be captured")

            # 1. Test Tools List
            logger.info("Testing 'tools/list'...")
            tools = await client.get_tools_config()
            tool_names = [t['name'] for t in tools]
            self.assertIn("read_db", tool_names)
            self.assertIn("send_slack", tool_names)
            logger.info(f"Tools found: {tool_names}")

            # 2. Test Allowed Tool (read_db) with Spotlighting
            logger.info("Testing allowed tool 'read_db'...")
            mock_query = "SELECT * FROM users"
            result = await client.execute_tool("read_db", {"query": mock_query})
            
            # Check for Spotlighting in 'content'
            self.assertIn("content", result)
            content_items = result["content"]
            self.assertTrue(len(content_items) > 0)
            text_content = content_items[0]["text"]
            
            logger.info(f"Read DB Result: {text_content}")
            
            # Verify Spotlighting Delimiters
            self.assertIn("<<<SENTINEL_DATA_START:", text_content)
            self.assertIn(">>>", text_content)
            self.assertIn(mock_query, text_content)
            
            # 3. Test Denied Tool (send_slack) - Implicit Deny
            logger.info("Testing denied tool 'send_slack'...")
            try:
                await client.execute_tool("send_slack", {"msg": "Should fail"})
                self.fail("Tool 'send_slack' should have been blocked")
            except RuntimeError as e:
                logger.info(f"Blocked correctly: {e}")
                self.assertIn("forbidden by static policy", str(e))

    def test_full_flow(self):
        # Run the async test in the event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.run_integration_test())
        finally:
            loop.close()


if __name__ == "__main__":
    unittest.main()
