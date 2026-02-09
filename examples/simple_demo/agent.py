# Copyright 2026 BadCompany
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import os
import sys
import logging

# Standard Lilith path resolution
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "sdk", "src"))
from lilith_zero import Lilith, PolicyViolationError

# Optional: Enable logging to see Lilith's internal audit trail
# logging.basicConfig(level=logging.INFO)

# Configuration
LILITH_BIN = os.getenv("LILITH_ZERO_BINARY_PATH", os.path.join(PROJECT_ROOT, "lilith-zero/target/release/lilith-zero.exe"))
MOCK_SERVER = os.path.join(os.path.dirname(__file__), "mock_server.py")
POLICY_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "policy.yaml"))

async def run_minimal_demo():
    print("--- Lilith Minimal Demo ---")
    
    # 1. Start Lilith with an upstream tool server
    async with Lilith(
        upstream=f"python -u {MOCK_SERVER}",
        policy=POLICY_FILE,
        binary=LILITH_BIN
    ) as lilith:
        print(f"Session Active: {lilith.session_id[:20]}...")

        # 2. List available tools
        tools = await lilith.list_tools()
        print(f"Discovered {len(tools)} tools: {[t['name'] for t in tools]}")

        # 3. Call an ALLOWED tool
        print("\nCalling 'ping' (ALLOWED by policy)...")
        try:
            res = await lilith.call_tool("ping", {})
            print(f"Result: {res['content'][0]['text']}")
        except Exception as e:
             print(f"Error during ping: {e}")

        # 4. Call a DENIED tool
        print("\nCalling 'read_db' (DENIED by policy)...")
        try:
            await lilith.call_tool("read_db", {"query": "SELECT * FROM secrets"})
        except PolicyViolationError as e:
            print(f"Blocked Correctly: {e}")
        except Exception as e:
            print(f"Unexpected Error: {e}")

if __name__ == "__main__":
    asyncio.run(run_minimal_demo())
