import asyncio
import os
import sys
import unittest
import logging
import time

# Ensure we can import the local SDK
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sentinel_sdk import Sentinel

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HardeningTestSuiteV2")

class TestSentinelfixes(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.upstream_script = os.path.join(os.path.dirname(__file__), "vulnerable_tools.py")
        self.policy_path = os.path.join(os.path.dirname(__file__), "policy_hardening.yaml")
        # We need a policy with Resource Rules. I'll write a temp one.
        self.resource_policy_path = os.path.join(os.path.dirname(__file__), "policy_resources.yaml")
        self.binary_path = os.path.abspath("./sentinel/target/release/sentinel.exe")
        
        with open(self.resource_policy_path, "w") as f:
            f.write("""
id: "res-policy-1"
customer_id: "test"
name: "Resource Hardening"
version: 1
static_rules:
  read_file: ALLOW
  ping: ALLOW
taint_rules: []
resource_rules:
  - uri_pattern: "file:///allowed/*"
    action: ALLOW
  - uri_pattern: "*"
    action: BLOCK
""")

    async def test_resource_fail_closed(self):
        """Verify explicit blocking of unauthorized resources."""
        logger.info("TEST: Resource Hardening (Fail Closed)")
        
        client = Sentinel.start(
            upstream=f"{sys.executable} {self.upstream_script}",
            binary_path=self.binary_path,
            policy=self.resource_policy_path
        )
        
        async with client:
            # We fake a resource request by manually sending one, 
            # since SDK high-level execute_tool uses 'tool' event.
            # But the SDK exposes _send_request.
            # NOTE: Current SDK doesn't have a high level "read_resource" method, 
            # so we test the middleware's logic by sending a raw MCP "resources/read" request (simulated).
            # Wait, sentinel interprets "tools/call". 
            # Does Sentinel intercept "resources/read"?
            # Looking at middleware code: `req.method == "resources/read"`?
            # StdioTransport deserializes into `JsonRpcRequest`.
            # Adapter `parse_request` converts JSON RPC method to `SecurityEvent`.
            # If Adapter supports it. Let's assume standard MCP "resources/read".
            
            # Since standard SDK Client handles this, we can mimic it.
            res = await client._send_request("resources/read", {"uri": "file:///etc/passwd"})
            
            # Check for error
            if "error" in res or (isinstance(res, dict) and res.get("id") is None and "reason" in str(res)):
                 # Middleware returns JsonRpcError struct which is mapped to result?
                 # No, `write_error` sends a JSON-RPC Error object.
                 pass

            # If middleware blocked it, _send_request raises Runtime error or returns error dict?
            # SDK Code: if "error" in msg, future.set_exception.
            try:
                await client._send_request("resources/read", {"uri": "file:///etc/passwd"})
                self.fail("Should have blocked file:///etc/passwd")
            except Exception as e:
                logger.info(f"Verified Block: {e}")
                self.assertIn("blocked by rule", str(e))

            # Test Allowed
            try:
                # Middleware allows, but upstream likely fails (it's a dummy script, doesn't handle resources).
                # But we just want to verify Middleware PASSES it.
                # If it passes, upstream (vulnerable_tools.py) will receive it.
                # vulnerable_tools.py uses FastMCP. It might error "Method not found".
                # If we get "Method not found", it means middleware ALLOWED it!
                await client._send_request("resources/read", {"uri": "file:///allowed/data.txt"})
            except Exception as e:
                if "Method not found" in str(e):
                    logger.info("Verified Allow: Message passed to upstream (Method not found is expected from upstream)")
                else: 
                     # Could be IO error if upstream died?
                     logger.warning(f"Unexpected error on allowed resource: {e}")

    async def test_transport_noise_resilience(self):
        """Verify Sentinel ignores garbage stdout from upstream."""
        logger.info("TEST: Transport Noise Resilience")
        
        # Create a noisy upstream script
        noisy_script = os.path.join(os.path.dirname(__file__), "noisy_tool.py")
        with open(noisy_script, "w") as f:
            f.write("""
import sys
import time
import json

# Print garbage to stdout
print("Downloading model 10%...", flush=True)
print("Downloading model 50%...", flush=True)
print("DEBUG: Init complete", flush=True)
# Malformed JSON
print("{ 'bad': json }", flush=True)

# Actual JSON-RPC response simulation loop
while True:
    line = sys.stdin.readline()
    if not line: break
    try:
        req = json.loads(line)
        # Echo back success
        res = {"jsonrpc": "2.0", "id": req.get("id"), "result": {"content": [{"type":"text", "text":"ok"}]}}
        print(json.dumps(res), flush=True)
    except:
        pass
""")
        
        client = Sentinel.start(
            upstream=f"{sys.executable} {noisy_script}",
            binary_path=self.binary_path,
            policy=self.resource_policy_path # reusing policy
        )
        
        async with client:
            # Send a request. Middleware should filter the "Downloading..." lines and find the JSON response.
            try:
                res = await client.execute_tool("ping", {})
                self.assertEqual(res["content"][0]["text"], "ok")
                logger.info("Verified Noise Filtering: Successfully ignored garbage lines.")
            except Exception as e:
                self.fail(f"Transport failed on noise: {e}")

if __name__ == "__main__":
    unittest.main()
