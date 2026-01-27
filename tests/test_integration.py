"""
Sentinel Integration Tests

Tests end-to-end functionality using the Sentinel.start() API.
Binary discovery is automatic via SENTINEL_BINARY_PATH environment variable
or PATH lookup.
"""
import pytest
import os
import sys
import logging

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_sdk import Sentinel

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("IntegrationTest")

# Test configuration - relative paths
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TEST_DIR)
POLICY_PATH = os.path.join(TEST_DIR, "policy.yaml")
UPSTREAM_SCRIPT = os.path.join(PROJECT_ROOT, "examples", "vulnerable_tools.py")
UPSTREAM_CMD = f"{sys.executable} -u {UPSTREAM_SCRIPT}"

@pytest.mark.asyncio
async def test_full_integration_flow():
    # Verify test files exist
    assert os.path.exists(POLICY_PATH), f"Policy file not found at {POLICY_PATH}"
    assert os.path.exists(UPSTREAM_SCRIPT), f"Upstream script not found at {UPSTREAM_SCRIPT}"

    logger.info("Initializing Sentinel Client...")
    
    try:
        client = Sentinel.start(
            upstream=UPSTREAM_CMD,
            policy=POLICY_PATH,
            security_level="high"
        )
    except FileNotFoundError as e:
        pytest.fail(f"Sentinel binary not found: {e}. Set SENTINEL_BINARY_PATH.")
    
    async with client:
        logger.info(f"Session Started: {client.session_id}")
        assert client.session_id is not None, "Session ID should be captured"

        # 1. Test Tools List
        logger.info("Testing 'tools/list'...")
        tools = await client.get_tools_config()
        tool_names = [t['name'] for t in tools]
        assert "read_db" in tool_names
        assert "send_slack" in tool_names
        logger.info(f"Tools found: {tool_names}")

        # 2. Test Allowed Tool (read_db) with Spotlighting
        logger.info("Testing allowed tool 'read_db'...")
        mock_query = "SELECT * FROM users"
        result = await client.execute_tool("read_db", {"query": mock_query})
        
        # Check for Spotlighting in 'content'
        assert "content" in result
        content_items = result["content"]
        assert len(content_items) > 0
        text_content = content_items[0]["text"]
        
        logger.info(f"Read DB Result: {text_content}")
        
        # Verify Spotlighting Delimiters
        assert "<<<SENTINEL_DATA_START:" in text_content
        assert ">>>" in text_content
        assert mock_query in text_content
        
        # 3. Test Denied Tool (send_slack) - Implicit Deny
        logger.info("Testing denied tool 'send_slack'...")
        try:
            await client.execute_tool("send_slack", {"msg": "Should fail"})
            pytest.fail("Tool 'send_slack' should have been blocked")
        except RuntimeError as e:
            logger.info(f"Blocked correctly: {e}")
            assert "forbidden by static policy" in str(e)
