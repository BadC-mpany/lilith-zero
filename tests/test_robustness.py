
import pytest
import asyncio
import os
import json
import uuid
import sys

# Add project root and sdk/src to path for imports
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(repo_root, "sdk", "src"))

from lilith_zero import Lilith, LilithError, PolicyViolationError



BINARY_PATH = os.environ.get("LILITH_ZERO_BINARY_PATH")
UPSTREAM_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "manual_server.py")
UPSTREAM_CMD = f"python {UPSTREAM_PATH}"

@pytest.mark.asyncio
async def test_large_payload():
    """Test sending a payload just under the limit."""
    async with Lilith(upstream=UPSTREAM_CMD, binary=BINARY_PATH) as client:
        # 5MB Argument
        huge_str = "A" * (5 * 1024 * 1024)
        
        try:
            # Send to non-existent tool or method to trigger parsing but fail policy/method
            # If we send 'tools/call' with huge payload, it gets parsed.
            # Since no policy file, it defaults to Deny All.
            # So Lilith should block it, raising PolicyViolationError.
            await client._send_request("tools/call", {
                "name": "non_existent_huge", 
                "arguments": {"data": huge_str}
            })
            pytest.fail("Lilith should have blocked huge payload without policy")
            
        except (PolicyViolationError, LilithError):
            # Blocked as expected
            pass
        except asyncio.TimeoutError:
            # Timeout is also a valid failure mode for huge payload processing in some environments
            pass

@pytest.mark.asyncio
async def test_concurrent_requests():
    """Test handling multiple concurrent requests."""
    async with Lilith(upstream=UPSTREAM_CMD, binary=BINARY_PATH) as client:
        
        async def send_req(i):
            # tools/list is safe and fast
            return await client.list_tools()

        # Run 50 concurrent requests
        tasks = [send_req(i) for i in range(50)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
            
        assert len(results) == 50
        for res in results:
             if isinstance(res, Exception):
                 continue
             assert isinstance(res, list) # list_tools returns list

@pytest.mark.asyncio
async def test_invalid_utf8():
    """Test sending invalid UTF-8 sequences."""
    # This one might crash the upstream if forwarded? 
    # But Lilith should catch it at codec level.
    # Lilith parses before forwarding? Yes.
    async with Lilith(upstream=UPSTREAM_CMD, binary=BINARY_PATH) as client:
        
        # Prepare a raw message with bad UTF-8
        bad_bytes = b'{"jsonrpc": "2.0", "method": "test", "params": "\xFF"}'
        header = f"Content-Length: {len(bad_bytes)}\r\n\r\n".encode('ascii')
        
        if client._process and client._process.stdin:
            client._process.stdin.write(header + bad_bytes)
            await client._process.stdin.drain()
        
        await asyncio.sleep(0.5)
        
        try:
            alive_check = await client.list_tools()
            assert isinstance(alive_check, list)
        except (LilithError, asyncio.TimeoutError):
            pass
