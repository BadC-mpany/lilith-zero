#!/usr/bin/env python3
"""
Test script for MCP JSON-RPC 2.0 Protocol Implementation

This script tests:
1. tools/list endpoint
2. tools/call endpoint (with token verification)
3. Error handling
4. Full interceptor → MCP flow
"""

import os
import sys
import json
import uuid
import httpx
import jwt
import time
from pathlib import Path

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent / "sentinel_core" / "shared" / "python" / "src"))
sys.path.insert(0, str(Path(__file__).parent / "sentinel_core" / "interceptor" / "python" / "src"))

from crypto_utils import CryptoUtils

# Configuration
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:9000")
INTERCEPTOR_URL = os.getenv("INTERCEPTOR_URL", "http://localhost:8000")
API_KEY = os.getenv("SENTINEL_API_KEY", "sk_live_demo_123")

# Load signing key for token generation
INTERCEPTOR_PRIVATE_KEY_PATH = Path(__file__).parent / "sentinel_core" / "secrets" / "interceptor_private.pem"


def generate_test_token(tool_name: str, args: dict) -> str:
    """Generate a test JWT token for MCP authentication."""
    if not INTERCEPTOR_PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError(f"Private key not found at {INTERCEPTOR_PRIVATE_KEY_PATH}")
    
    with open(INTERCEPTOR_PRIVATE_KEY_PATH, "rb") as f:
        signing_key = f.read()
    
    now = time.time()
    token_payload = {
        "iss": "sentinel-interceptor",
        "sub": str(uuid.uuid4()),
        "scope": f"tool:{tool_name}",
        "p_hash": CryptoUtils.hash_params(args),
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 60  # 60 second expiry for testing
    }
    
    return jwt.encode(token_payload, signing_key, algorithm="EdDSA")


def test_tools_list():
    """Test the tools/list JSON-RPC 2.0 endpoint."""
    print("\n" + "="*70)
    print("TEST 1: tools/list endpoint")
    print("="*70)
    
    request = {
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": str(uuid.uuid4())
    }
    
    try:
        response = httpx.post(MCP_SERVER_URL, json=request, timeout=5.0)
        response.raise_for_status()
        
        result = response.json()
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(result, indent=2)}")
        
        if result.get("jsonrpc") == "2.0" and "result" in result:
            tools = result["result"].get("tools", [])
            print(f"\n✓ Success! Found {len(tools)} tools")
            if tools:
                print(f"  First tool: {tools[0].get('name')}")
            return True
        else:
            print(f"\n✗ Failed: Invalid response format")
            return False
            
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False


def test_tools_call_valid():
    """Test tools/call with a valid token."""
    print("\n" + "="*70)
    print("TEST 2: tools/call endpoint (valid token)")
    print("="*70)
    
    tool_name = "read_file"
    tool_args = {"path": "/etc/test.txt"}
    
    token = generate_test_token(tool_name, tool_args)
    
    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": tool_args
        },
        "id": str(uuid.uuid4())
    }
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = httpx.post(MCP_SERVER_URL, json=request, headers=headers, timeout=5.0)
        response.raise_for_status()
        
        result = response.json()
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(result, indent=2)}")
        
        if result.get("jsonrpc") == "2.0" and "result" in result:
            print(f"\n✓ Success! Tool executed successfully")
            print(f"  Result: {result['result']}")
            return True
        elif "error" in result:
            print(f"\n✗ Failed: {result['error'].get('message')}")
            return False
        else:
            print(f"\n✗ Failed: Invalid response format")
            return False
            
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False


def test_tools_call_invalid_token():
    """Test tools/call with an invalid token."""
    print("\n" + "="*70)
    print("TEST 3: tools/call endpoint (invalid token)")
    print("="*70)
    
    tool_name = "read_file"
    tool_args = {"path": "/etc/test.txt"}
    
    # Use an invalid token
    invalid_token = "invalid.token.here"
    
    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": tool_args
        },
        "id": str(uuid.uuid4())
    }
    
    headers = {"Authorization": f"Bearer {invalid_token}"}
    
    try:
        response = httpx.post(MCP_SERVER_URL, json=request, headers=headers, timeout=5.0)
        result = response.json()
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(result, indent=2)}")
        
        if "error" in result:
            error_msg = result["error"].get("message", "")
            if "Invalid Signature" in error_msg or "Token" in error_msg:
                print(f"\n✓ Success! Correctly rejected invalid token")
                return True
            else:
                print(f"\n✗ Failed: Unexpected error: {error_msg}")
                return False
        else:
            print(f"\n✗ Failed: Should have returned an error")
            return False
            
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False


def test_tools_call_missing_auth():
    """Test tools/call without Authorization header."""
    print("\n" + "="*70)
    print("TEST 4: tools/call endpoint (missing Authorization)")
    print("="*70)
    
    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/etc/test.txt"}
        },
        "id": str(uuid.uuid4())
    }
    
    try:
        response = httpx.post(MCP_SERVER_URL, json=request, timeout=5.0)
        result = response.json()
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(result, indent=2)}")
        
        if "error" in result:
            error_msg = result["error"].get("message", "")
            if "Authorization" in error_msg or "Missing" in error_msg:
                print(f"\n✓ Success! Correctly rejected request without auth")
                return True
            else:
                print(f"\n✗ Failed: Unexpected error: {error_msg}")
                return False
        else:
            print(f"\n✗ Failed: Should have returned an error")
            return False
            
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False


def test_invalid_method():
    """Test with an invalid method name."""
    print("\n" + "="*70)
    print("TEST 5: Invalid method name")
    print("="*70)
    
    request = {
        "jsonrpc": "2.0",
        "method": "invalid/method",
        "id": str(uuid.uuid4())
    }
    
    try:
        response = httpx.post(MCP_SERVER_URL, json=request, timeout=5.0)
        result = response.json()
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(result, indent=2)}")
        
        if "error" in result:
            error_code = result["error"].get("code")
            if error_code == -32601:  # METHOD_NOT_FOUND
                print(f"\n✓ Success! Correctly returned METHOD_NOT_FOUND")
                return True
            else:
                print(f"\n✗ Failed: Unexpected error code: {error_code}")
                return False
        else:
            print(f"\n✗ Failed: Should have returned an error")
            return False
            
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False


def test_interceptor_flow():
    """Test the full interceptor → MCP flow."""
    print("\n" + "="*70)
    print("TEST 6: Full Interceptor → MCP flow")
    print("="*70)
    
    session_id = str(uuid.uuid4())
    tool_name = "read_file"
    tool_args = {"path": "/etc/test.txt"}
    
    request = {
        "session_id": session_id,
        "tool_name": tool_name,
        "args": tool_args
    }
    
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        response = httpx.post(
            f"{INTERCEPTOR_URL}/v1/proxy-execute",
            json=request,
            headers=headers,
            timeout=10.0
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2)}")
            print(f"\n✓ Success! Full flow completed")
            return True
        else:
            error_detail = response.json().get("detail", response.text)
            print(f"Error: {error_detail}")
            print(f"\n✗ Failed: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("MCP JSON-RPC 2.0 Protocol Test Suite")
    print("="*70)
    print(f"MCP Server URL: {MCP_SERVER_URL}")
    print(f"Interceptor URL: {INTERCEPTOR_URL}")
    print("="*70)
    
    results = []
    
    # Test 1: tools/list
    results.append(("tools/list", test_tools_list()))
    
    # Test 2: tools/call with valid token
    results.append(("tools/call (valid)", test_tools_call_valid()))
    
    # Test 3: tools/call with invalid token
    results.append(("tools/call (invalid token)", test_tools_call_invalid_token()))
    
    # Test 4: tools/call without auth
    results.append(("tools/call (no auth)", test_tools_call_missing_auth()))
    
    # Test 5: Invalid method
    results.append(("Invalid method", test_invalid_method()))
    
    # Test 6: Full interceptor flow
    results.append(("Interceptor → MCP flow", test_interceptor_flow()))
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print("="*70)
    print(f"Total: {passed}/{total} tests passed")
    print("="*70)
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

