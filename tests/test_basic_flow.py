import asyncio
import os
import sys
import unittest
import logging

# Add project root and sdk/src to path for imports
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(repo_root, "sdk", "src"))
from lilith_zero import Lilith
from lilith_zero.exceptions import PolicyViolationError

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("BasicFlowTest")

class TestBasicFlow(unittest.IsolatedAsyncioTestCase):
    """
    Lilith Basic Flow Tests.
    Verifies end-to-end functionality using the Lilith.start() API.
    """

    async def asyncSetUp(self):
        self.test_dir = os.path.dirname(os.path.abspath(__file__))
        self.policy_path = os.path.join(self.test_dir, "policy.yaml")
        self.upstream_script = os.path.join(self.test_dir, "resources", "manual_server.py")
        self.upstream_cmd = f"{sys.executable} -u {self.upstream_script}"
        
        if not os.path.exists(self.policy_path):
            self.fail(f"Policy file not found at {self.policy_path}")
        if not os.path.exists(self.upstream_script):
            self.fail(f"Upstream script not found at {self.upstream_script}")

    async def test_full_integration_flow(self):
        logger.info("Initializing Lilith Client...")
        
        client = Lilith(
            upstream=self.upstream_cmd,
            policy=self.policy_path,
        )
        
        async with client:
            logger.info(f"Session Started: {client.session_id}")
            self.assertIsNotNone(client.session_id)

            # 1. Test Tools List
            logger.info("Testing 'tools/list'...")
            tools = await client.list_tools()
            tool_names = [t['name'] for t in tools]
            self.assertIn("read_db", tool_names)
            self.assertIn("send_slack", tool_names)

            # 2. Test Allowed Tool (read_db) with Spotlighting
            logger.info("Testing allowed tool 'read_db'...")
            mock_query = "SELECT * FROM users"
            result = await client.call_tool("read_db", {"query": mock_query})
            
            # Check for Spotlighting in 'content'
            self.assertIn("content", result)
            text_content = result["content"][0]["text"]
            
            # Verify Spotlighting Delimiters
            self.assertIn("<<<LILITH_ZERO_DATA_START:", text_content)
            self.assertIn(mock_query, text_content)
            
            # 3. Test Denied Tool (send_slack) - Explicit Deny in policy.yaml
            logger.info("Testing denied tool 'send_slack'...")
            try:
                await client.call_tool("send_slack", {"msg": "Should fail"})
                self.fail("Tool 'send_slack' should have been blocked")
            except PolicyViolationError as e:
                logger.info(f"Blocked correctly: {e}")
                self.assertIn("forbidden by static policy", str(e))

if __name__ == "__main__":
    unittest.main()
