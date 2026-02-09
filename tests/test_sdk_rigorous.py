
import pytest
import asyncio
import os
import sys
from typing import Dict, Any

# Add project root and sdk/src to path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)
sys.path.insert(0, os.path.join(repo_root, "sdk", "src"))

from lilith_zero import (
    Lilith, 
    LilithError, 
    LilithConfigError, 
    LilithConnectionError, 
    LilithProcessError, 
    PolicyViolationError,
    client as lilith_client
)

BINARY_PATH = os.environ.get("LILITH_ZERO_BINARY_PATH")

@pytest.fixture
def fast_timeout(monkeypatch):
    """Set the session timeout to be very short for tests."""
    monkeypatch.setattr(lilith_client, "_SESSION_TIMEOUT_SEC", 1.0)
    monkeypatch.setattr(lilith_client, "_SESSION_POLL_INTERVAL_SEC", 0.1)

@pytest.mark.asyncio
async def test_config_error_missing_upstream():
    """Rigorously verify LilithConfigError for missing upstream."""
    with pytest.raises(LilithConfigError) as excinfo:
        Lilith(upstream="")
    
    assert excinfo.value.config_key == "upstream"

@pytest.mark.asyncio
async def test_config_error_invalid_binary():
    """Rigorously verify LilithConfigError for non-existent binary."""
    # Use a path that is definitely not there
    with pytest.raises(LilithConfigError) as excinfo:
        Lilith(upstream="python", binary="C:\\non\\existent\\lilith_binary_at_all_123.exe")
    
    assert excinfo.value.config_key == "binary"

@pytest.mark.asyncio
async def test_connection_error_spawn_failed():
    """Test connection failure at 'spawn' phase by using an invalid binary."""
    # Use repo_root as 'binary' (it's a directory, not an executable)
    with pytest.raises(LilithConnectionError) as excinfo:
        async with Lilith(upstream="python", binary=repo_root) as client:
            pass
    
    assert excinfo.value.phase == "spawn"

@pytest.mark.asyncio
async def test_connection_error_handshake_timeout(fast_timeout):
    """Test handshake timeout using a dummy binary that never outputs a session ID."""
    # We use sys.executable (python.exe). 
    # It starts but won't print LILITH_ZERO_SESSION_ID=...
    # Note: Lilith runs 'binary --policy ...' so python will just exit with error.
    with pytest.raises(LilithConnectionError) as excinfo:
        async with Lilith(upstream="python", binary=sys.executable) as client:
            pass
    
    assert excinfo.value.phase == "handshake"

@pytest.mark.asyncio
async def test_policy_violation_rich_context():
    """Verify that PolicyViolationError is raised with context and details."""
    policy_path = "tests/policy.yaml"
    cmd = "python -u tests/resources/manual_server.py"
    
    if not BINARY_PATH:
        pytest.skip("LILITH_ZERO_BINARY_PATH not set")

    async with Lilith(cmd, policy=policy_path, binary=BINARY_PATH) as client:
        with pytest.raises(PolicyViolationError) as excinfo:
            await client.call_tool("send_slack", {"msg": "hello"})
        
        assert "policy_details" in excinfo.value.context

@pytest.mark.asyncio
async def test_runtime_health_check():
    """Test detection of process death during runtime via health check."""
    cmd = "python -u tests/resources/manual_server.py"
    
    if not BINARY_PATH:
        pytest.skip("LILITH_ZERO_BINARY_PATH not set")

    async with Lilith(cmd, binary=BINARY_PATH) as client:
        await client.list_tools() # Ensure up
        
        # Kill the process (Lilith binary itself)
        if client._process:
            client._process.kill()
            await client._process.wait()
        
        # Next call should fail immediately due to health check in _send_request
        with pytest.raises(LilithConnectionError) as excinfo:
            await client.list_tools()
        
        assert excinfo.value.phase == "runtime"
        assert "not running" in excinfo.value.message.lower()

@pytest.mark.asyncio
async def test_tool_execution_error_captures_context():
    """Verify that RPC errors capture code and data in context."""
    cmd = "python -u tests/resources/manual_server.py"
    
    if not BINARY_PATH:
        pytest.skip("LILITH_ZERO_BINARY_PATH not set")

    async with Lilith(cmd, binary=BINARY_PATH) as client:
        # Simulate an RPC error by sending a non-existent method
        with pytest.raises(LilithError) as excinfo:
            await client._send_request("non_existent_method", {})
        
        assert "code" in excinfo.value.context
        assert "RPC Error" in str(excinfo.value)
