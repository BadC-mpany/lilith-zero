import os
import sys
import pytest
import asyncio
import time

# Add project root and sdk/src to path for imports
repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(repo_root, "sdk", "src"))

from lilith_zero import Lilith
from lilith_zero.exceptions import LilithError, LilithConnectionError

@pytest.mark.asyncio
async def test_slowloris_attack():
    """
    Simulate a Slowloris-style attack by dripping bytes slowly into the codec.
    This tests the timeout and framing robustness of the Rust middleware.
    """
    # We need a mock server that drips data
    # For this test, we might need a more low-level way to interact with Lilith
    # but let's try a simple timeout test first.
    
    # Start Lilith with a mock that just drips a few bytes but never completes a message
    # 'python -c "import time; sys.stdout.write(\"Content-Length: 10\\n\\n\"); sys.stdout.flush(); time.sleep(10)"'
    
    cmd = 'python -c "import time, sys; sys.stdout.write(\'Content-Length: 10\\r\\n\\r\\n\'); sys.stdout.flush(); time.sleep(5)"'
    
    start_time = time.time()
    try:
        async with Lilith(cmd, policy="tests/resources/v0_1_0_policy.yaml") as s:
            # The client should probably time out during the handshake or first call
            await asyncio.wait_for(s.list_tools(), timeout=3.0)
    except (asyncio.TimeoutError, LilithError) as e:
        # Success: The middleware/client correctly prevented a hang
        pass
    
    duration = time.time() - start_time
    assert duration < 40.0, "Middleware took too long to handle slow drip"

@pytest.mark.asyncio
async def test_huge_payload():
    """
    Send a massive payload to test memory limits and buffer safety.
    """
    # Create a 10MB payload (should be rejected by default settings)
    huge_data = "A" * (10 * 1024 * 1024)
    
    try:
        async with Lilith("python examples/simple_demo/mock_server.py", policy="tests/resources/v0_1_0_policy.yaml") as s:
            await s.call_tool("echo", {"text": huge_data})
    except Exception as e:
        # Success: The connection was broken or limit exceeded
        error_msg = str(e).lower()
        assert "exceeds max limit" in error_msg or "broken pipe" in error_msg or "connection" in error_msg
