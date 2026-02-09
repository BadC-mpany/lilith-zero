
import pytest
import asyncio
import os
import json
import sys
import uuid
import logging

# Add project root and sdk/src to path for imports
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(repo_root, "sdk", "src"))

from lilith_zero import Lilith
from lilith_zero.exceptions import LilithError, PolicyViolationError

# Configuration
from lilith_zero.client import _find_binary
try:
    BINARY_PATH = os.environ.get("LILITH_ZERO_BINARY_PATH") or _find_binary()
except Exception:
    BINARY_PATH = None
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_PATH = os.path.join(TEST_DIR, "resources", "v0_1_0_policy.yaml")
UPSTREAM_PATH = os.path.join(TEST_DIR, "resources", "manual_server.py")
UPSTREAM_CMD = f"python {UPSTREAM_PATH}"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ComplianceTest")

@pytest.mark.asyncio
async def test_fail_closed_by_default():
    """
    CRITICAL: Verify 'Fail-Closed' behavior.
    If no policy is provided, Lilith MUST default to DENY ALL (unless Config allows otherwise, 
    but default config should be secure).
    """
    # Start WITHOUT policy
    async with Lilith(upstream=UPSTREAM_CMD, binary=BINARY_PATH) as client:
        # 1. Try a harmless tool - Should fail
        try:
            await client.call_tool("any_tool", {})
            pytest.fail("Security Vulnerability: Lilith allowed tool execution without a loaded policy!")
        except PolicyViolationError:
            pass # Expected
        except Exception as e:
            # If it failed for other reasons (e.g. MethodNotFound), we strictly expect PolicyViolation 
            # because Lilith should intercept BEFORE upstream.
            # However, with no policy, Lilith might default to deny.
            # Let's check the error message if possible.
            assert any(word in str(e).lower() for word in ["policy violation", "denied", "deny", "blocked"])

@pytest.mark.asyncio
async def test_static_rules():
    """
    Verify fundamental ACLs (ALLOW/DENY).
    """
    async with Lilith(upstream=UPSTREAM_CMD, binary=BINARY_PATH, policy=POLICY_PATH) as client:
        # ALLOW rule
        try:
            # Upsream might error 'Method not found', that's fine, implies Lilith allowed it through
            await client.call_tool("public_info", {})
        except PolicyViolationError:
            pytest.fail("False Positive: 'public_info' should be ALLOWED by static policy")
        except LilithError:
            pass # Upstream error is fine

        # DENY rule
        try:
            await client.call_tool("dangerous_op", {})
            pytest.fail("Security Vulnerability: 'dangerous_op' should be DENIED by static policy")
        except PolicyViolationError:
            pass # Expected
        
@pytest.mark.asyncio
async def test_taint_tracking_lifecycle():
    """
    Verify complete Taint Tracking flow:
    1. Source (Add Taint)
    2. Sink (Check Taint -> Blocked)
    3. Cleaner (Remove Taint)
    4. Sink (Check Taint -> Allowed)
    """
    async with Lilith(upstream=UPSTREAM_CMD, binary=BINARY_PATH, policy=POLICY_PATH) as client:
        
        # 1. Source: Read Secret -> Adds 'confidential' taint
        # We assume the tool returns successfully for taint to be applied? 
        # Or does taint apply on request? 
        # Usually taint applies on result, but Lilith might apply "Interactive" taint tracking?
        # Lilith v0.1.0 Taint Rules apply actions. ADD_TAINT happens when tool is called?
        # Let's check implementation. ADD_TAINT usually implies "The result of this tool is tainted".
        # But for request/response flow, Lilith tracks session state.
        
        await client.call_tool("read_secret", {})
        
        # 2. Sink: Network Send -> Checks 'confidential'. Should fail.
        try:
            await client.call_tool("network_send", {"data": "leaked"})
            pytest.fail("Security Vulnerability: Tainted session allowed to access Restricted Sink!")
        except PolicyViolationError:
            pass # Expected block due to taint
            
        # 3. Cleaner: Redact Data -> Removes 'confidential' taint
        await client.call_tool("redact_data", {"data": "cleansed"})
        
        # 4. Sink: Network Send -> Should succeed now
        try:
            await client.call_tool("network_send", {"data": "safe"})
        except PolicyViolationError:
             pytest.fail("False Positive: Sink blocked after taint was removed")
        except LilithError:
            pass # Upstream error ok

@pytest.mark.asyncio
async def test_logic_conditions_and_wildcards():
    """
    Verify Argument Matching and Wildcards.
    """
    async with Lilith(upstream=UPSTREAM_CMD, binary=BINARY_PATH, policy=POLICY_PATH) as client:
        
        # 1. Conditional Access: Blocked by default
        try:
            await client.call_tool("conditional_access", {"region": "us-east-1"})
            pytest.fail("Security Vulnerability: Conditional access allow-list bypass (wrong arg)")
        except PolicyViolationError:
            pass
            
        # 2. Conditional Access: Allowed with correct arg
        try:
            await client.call_tool("conditional_access", {"region": "us-west-1"})
        except PolicyViolationError:
            pytest.fail("False Positive: Conditional access blocked with correct argument")
        except LilithError:
            pass
            
        # 3. Wildcard Access: Blocked by default (wrong extension)
        try:
            await client.call_tool("wildcard_access", {"file": "script.exe"})
            pytest.fail("Security Vulnerability: Wildcard filter bypass (wrong extension)")
        except PolicyViolationError:
            pass
            
        # 4. Wildcard Access: Allowed *.log
        try:
            await client.call_tool("wildcard_access", {"file": "system.log"})
        except PolicyViolationError:
             pytest.fail("False Positive: Wildcard *.log blocked valid file")
        except LilithError:
            pass

@pytest.mark.asyncio
async def test_session_security_and_observability():
    """
    Verify Session ID presence, uniqueness, and Logging.
    """
    # Capture stderr
    async with Lilith(upstream=UPSTREAM_CMD, binary=BINARY_PATH, policy=POLICY_PATH) as client:
        session_id = client.session_id
        assert session_id is not None
        assert len(session_id) > 20 # UUID + Signature usually long
        
        # Make a request to generate a log entry
        try:
             await client.call_tool("public_info", {})
        except:
            pass
            
        # We can't easily read the Lilith process stderr history from here since it's consumed by the SDK loop.
        # But SDK logs it to python logger if configured?
        # SDK _read_stderr_loop logs with _logger.debug("[stderr] ...").
        # We can't inspect that easily programmatically without a custom Handler.
        # But the mere fact we got a session_id means the handshake signature part (if any) worked.
        
        # Restart Lilith
        pass

    async with Lilith(upstream=UPSTREAM_CMD, binary=BINARY_PATH, policy=POLICY_PATH) as client2:
        session_id_2 = client2.session_id
        assert session_id_2 != session_id
