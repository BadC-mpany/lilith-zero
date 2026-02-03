import os
import sys
import asyncio
import json
import subprocess
import logging

# Configure logging to see Sentinel Stderr
logging.basicConfig(level=logging.DEBUG)

# Ensure sentinel_sdk is discoverable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../sentinel_sdk/src")))
from sentinel_sdk import Sentinel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BIN = os.path.abspath(os.path.join(BASE_DIR, "../../sentinel/target/debug/sentinel.exe"))
SENTINEL_BIN = os.getenv("SENTINEL_BINARY_PATH", DEFAULT_BIN)

async def test():
    """
    Windows Sandbox Verification using Sentinel SDK.
    """
    print(f"--- Sentinel Sandbox Verification (SDK Mode) ---")
    
    # TEST 1: Language Profile Generation
    print("\n[TEST 1] Testing Language Profile Generation...")
    async with Sentinel(
        upstream_cmd=sys.executable,
        upstream_args=[os.path.join(BASE_DIR, "mock_server.py")],
        language_profile="python:C:\\PythonTest",
        dry_run=True,
        binary_path=SENTINEL_BIN
    ) as sentinel:
        # For dry_run, we wait for the process to exit
        stdout_raw, _ = await sentinel.process.communicate()
        output = stdout_raw.decode()
        print("Dry run output:\n", output)
        if r"C:\\PythonTest" in output:
             print("SUCCESS: Profile correctly mapped.")
        else:
             print("FAILED: Profile root path not found.")

    # TEST 2: Strict Isolation Test
    print("\n[TEST 2] Testing Strict Isolation (File Breach)...")
    target_file = os.path.abspath(os.path.join(BASE_DIR, "../../CHANGELOG.md"))
    
    ps_cmd = "powershell.exe"
    ps_args = [
        "-NoProfile", "-Command", 
        f"try {{ Get-Content '{target_file}' -ErrorAction Stop; Write-Host 'BLOCKED'; }} catch {{ Write-Host 'BLOCKED'; }}"
    ]
    # Note: Use BLOCKED for both success/fail to verify tool execution but we look for "BREACH" to fail.
    # Actually, let's stick to the previous logic.
    ps_args = [
        "-NoProfile", "-Command", 
        f"try {{ Get-Content '{target_file}' -ErrorAction Stop; Write-Host 'BREACH'; }} catch {{ Write-Host 'BLOCKED'; }}"
    ]
    
    print(f"Launching Sentinel with SDK...")
    try:
        async with Sentinel(
            upstream_cmd=ps_cmd,
            upstream_args=ps_args,
            allow_read=["."], # Only allow current dir
            binary_path=SENTINEL_BIN,
            skip_handshake=True
        ) as sentinel:
            # We skip the handshake because powershell isn't an MCP server.
            # But the middleware won't spawn the tool until it gets a handshake!
            # OH! I see the issue. Sentinel requires a handshake to even START the tool.
            
            # So I MUST send a manual handshake if I skip the SDK's automatic one.
            await sentinel._send_notification("initialize", {
                "protocolVersion": "2024-11-05", # Legacy fallback
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            })
            # Wait, initialize is usually a request. 
            # If I send it as notification, Sentinel might log an error but still trigger the spawn?
            # No, let's send a proper request but don't wait for it.
            
            # Actually, the SDK has _send_request.
            # But await _send_request will wait for response.
            
            # Let's use the low-level write.
            handshake = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"}
                },
                "id": "handshake-1"
            }
            sentinel.process.stdin.write((json.dumps(handshake) + "\n").encode())
            await sentinel.process.stdin.drain()

            # Now wait for some output
            for _ in range(30):
                await asyncio.sleep(0.5)
                output = "\n".join(sentinel.stdout_lines + sentinel.stderr_lines)
                if "BLOCKED" in output or "BREACH" in output or "Upstream process terminated" in output:
                    break
            
            if "BLOCKED" in output or "Access is denied" in output:
                print("SUCCESS: File access was blocked.")
            elif "BREACH" in output:
                print("CRITICAL FAILURE: Sandbox breached!")
            else:
                print(f"INCONCLUSIVE: Output was:\n{output}")
    except Exception as e:
        print(f"Test caught error: {e}")

    print("\n[VERIFICATION]")
    print("1. Profile Generation: See TEST 1 results.")
    print("2. Sandbox Isolation: See TEST 2 results.")

if __name__ == "__main__":
    asyncio.run(test())
