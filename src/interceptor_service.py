import time
import uuid
import jwt
import httpx
import redis
from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from sentinel_core import CryptoUtils

# --- CONFIGURATION ---
# In a real SaaS, these would load from HashiCorp Vault or AWS Secrets Manager
try:
    with open("interceptor_private.pem", "rb") as f:
        SIGNING_KEY = f.read()
except FileNotFoundError:
    raise RuntimeError("Please run keygen.py first!")

# MOCK CUSTOMER DATABASE
# Maps API Keys -> Permissions & Infrastructure Details
CUSTOMER_DB = {
    "sk_live_demo_123": {
        "owner": "Demo User",
        # HIDDEN URL: The Agent does not know this.
        "mcp_upstream_url": "http://localhost:9000/execute",
        "policy": {
            # STATIC RULES (ACL)
            "static_rules": {
                "read_file": "ALLOW",
                "web_search": "ALLOW",
                "delete_db": "DENY"
            },
            # DYNAMIC RULES (Taint Logic)
            "taint_rules": [
                {
                    "tool": "read_file",
                    "action": "ADD_TAINT",
                    "tag": "sensitive_data"
                },
                {
                    "tool": "web_search",
                    "action": "CHECK_TAINT",
                    "forbidden_tags": ["sensitive_data"],
                    "error": "Exfiltration Blocked: Cannot search web after accessing sensitive files."
                }
            ]
        }
    }
}

app = FastAPI(title="Sentinel Interceptor (Zone B)")
redis_client = redis.Redis(host='localhost', port=6379, db=0)


class ProxyRequest(BaseModel):
    session_id: str
    tool_name: str
    args: Dict[str, Any]


@app.post("/v1/proxy-execute")
async def interceptor_proxy(req: ProxyRequest, x_api_key: str = Header(None)):
    """
    The Core Policy Engine.
    1. Authenticates Client via API Key.
    2. Checks Static & Dynamic Rules.
    3. Mints Capability Token (Ed25519).
    4. Proxies request to hidden MCP URL.
    """

    # 1. AUTHENTICATION
    if not x_api_key or x_api_key not in CUSTOMER_DB:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    customer_config = CUSTOMER_DB[x_api_key]
    policy = customer_config["policy"]

    # 2. STATIC RULE CHECK (ACL)
    permission = policy["static_rules"].get(req.tool_name, "DENY")
    if permission == "DENY":
        raise HTTPException(
            status_code=403, detail=f"Policy Violation: Tool '{req.tool_name}' is forbidden.")

    # 3. DYNAMIC STATE CHECK (Taint Analysis)
    taint_key = f"session:{req.session_id}:taints"
    # Get current session taints from Redis
    current_taints = {t.decode('utf-8')
                      for t in redis_client.smembers(taint_key)}

    # Check if this tool is blocked by existing taints
    for rule in policy["taint_rules"]:
        if rule["tool"] == req.tool_name and rule["action"] == "CHECK_TAINT":
            forbidden = set(rule["forbidden_tags"])
            if not current_taints.isdisjoint(forbidden):
                # We found an intersection -> BLOCK
                raise HTTPException(status_code=403, detail=rule["error"])

    # 4. MINT CAPABILITY (Cryptographic Binding)
    # This token proves to the MCP server that WE (The Interceptor) approved this.
    now = time.time()
    token_payload = {
        "iss": "sentinel-interceptor",
        "sub": req.session_id,
        "scope": f"tool:{req.tool_name}",
        "p_hash": CryptoUtils.hash_params(req.args),  # Binds args to signature
        # Nonce for Replay Protection
        "jti": str(uuid.uuid4()),
        "iat": now,
        # 5 Second TTL (Proxy is immediate)
        "exp": now + 5
    }

    signed_token = jwt.encode(token_payload, SIGNING_KEY, algorithm="EdDSA")

    # 5. SECURE PROXY EXECUTION
    # We call the MCP server. The Agent never sees the URL or the Token.
    upstream_url = customer_config["mcp_upstream_url"]

    async with httpx.AsyncClient() as client:
        try:
            mcp_response = await client.post(
                upstream_url,
                json={"tool": req.tool_name, "args": req.args},
                headers={"Authorization": f"Bearer {signed_token}"},
                timeout=5.0
            )
        except httpx.RequestError:
            raise HTTPException(
                status_code=502, detail="Upstream MCP Resource Unreachable")

    if mcp_response.status_code != 200:
        # Pass through error from MCP (e.g., Verification Failed)
        raise HTTPException(
            status_code=mcp_response.status_code, detail=mcp_response.text)

    # 6. STATE UPDATE (Side Effects)
    # If execution was successful, apply new taints
    for rule in policy["taint_rules"]:
        if rule["tool"] == req.tool_name and rule["action"] == "ADD_TAINT":
            redis_client.sadd(taint_key, rule["tag"])
            redis_client.expire(taint_key, 3600)  # 1 hour session TTL

    return mcp_response.json()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
