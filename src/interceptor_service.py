import time
import uuid
import jwt
import httpx
import redis
import yaml
import os
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Dict, Any, List, Optional
from .sentinel_core import CryptoUtils


# --- CONFIGURATION CLASSES ---
class PolicyRule(BaseModel):
    tool: str
    action: str
    tag: Optional[str] = None
    forbidden_tags: Optional[List[str]] = None
    error: Optional[str] = None


class PolicyDefinition(BaseModel):
    name: str
    static_rules: Dict[str, str]
    taint_rules: List[PolicyRule]


class CustomerConfig(BaseModel):
    owner: str
    mcp_upstream_url: str
    policy_name: str


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    interceptor_private_key_path: str = "secrets/interceptor_private.pem"
    policies_yaml_path: str = "policies.yaml"
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0


# --- GLOBAL CONFIGURATION LOAD ---
settings = Settings()

try:
    with open(settings.interceptor_private_key_path, "rb") as f:
        SIGNING_KEY = f.read()
except FileNotFoundError:
    raise RuntimeError(
        f"Private key not found at {settings.interceptor_private_key_path}. "
        "Please run keygen.py first!"
    )

CUSTOMERS: Dict[str, CustomerConfig] = {}
POLICIES: Dict[str, PolicyDefinition] = {}


def load_policies_from_yaml(file_path: str):
    """Loads customer and policy definitions from a YAML file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Policies YAML file not found at {file_path}")

    with open(file_path, 'r') as f:
        config = yaml.safe_load(f)

    # Load customers
    for customer_data in config.get("customers", []):
        api_key = customer_data.pop("api_key")
        CUSTOMERS[api_key] = CustomerConfig(**customer_data)

    # Load policies
    for policy_data in config.get("policies", []):
        policy_name = policy_data["name"]
        POLICIES[policy_name] = PolicyDefinition(**policy_data)

try:
    load_policies_from_yaml(settings.policies_yaml_path)
except Exception as e:
    raise RuntimeError(f"Failed to load policies from YAML: {e}")

app = FastAPI(title="Sentinel Interceptor (Zone B)")
redis_client = redis.Redis(
    host=settings.redis_host, port=settings.redis_port, db=settings.redis_db
)


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
    if not x_api_key or x_api_key not in CUSTOMERS:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    customer_config = CUSTOMERS[x_api_key]
    policy_definition = POLICIES.get(customer_config.policy_name)

    if not policy_definition:
        raise HTTPException(
            status_code=500, detail=f"Policy '{customer_config.policy_name}' not found."
        )

    # 2. STATIC RULE CHECK (ACL)
    permission = policy_definition.static_rules.get(req.tool_name, "DENY")
    if permission == "DENY":
        raise HTTPException(
            status_code=403, detail=f"Policy Violation: Tool '{req.tool_name}' is forbidden."
        )

    # 3. DYNAMIC STATE CHECK (Taint Analysis)
    taint_key = f"session:{req.session_id}:taints"
    # Get current session taints from Redis
    current_taints = {t.decode('utf-8') for t in redis_client.smembers(taint_key)}

    # Check if this tool is blocked by existing taints
    for rule in policy_definition.taint_rules:
        if rule.tool == req.tool_name and rule.action == "CHECK_TAINT":
            if rule.forbidden_tags:
                forbidden = set(rule.forbidden_tags)
                if not current_taints.isdisjoint(forbidden):
                    # We found an intersection -> BLOCK
                    raise HTTPException(status_code=403, detail=rule.error)

    # 4. MINT CAPABILITY (Cryptographic Binding)
    now = time.time()
    token_payload = {
        "iss": "sentinel-interceptor",
        "sub": req.session_id,
        "scope": f"tool:{req.tool_name}",
        "p_hash": CryptoUtils.hash_params(req.args),
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 5
    }

    signed_token = jwt.encode(token_payload, SIGNING_KEY, algorithm="EdDSA")

    # 5. SECURE PROXY EXECUTION
    upstream_url = customer_config.mcp_upstream_url

    async with httpx.AsyncClient() as client:
        try:
            mcp_response = await client.post(
                upstream_url,
                json={"tool": req.tool_name, "args": req.args},
                headers={"Authorization": f"Bearer {signed_token}"},
                timeout=5.0
            )
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=502, detail=f"Upstream MCP Resource Unreachable: {e}")

    if mcp_response.status_code != 200:
        raise HTTPException(
            status_code=mcp_response.status_code, detail=mcp_response.text)

    # 6. STATE UPDATE (Side Effects)
    for rule in policy_definition.taint_rules:
        if rule.tool == req.tool_name and rule.action == "ADD_TAINT":
            redis_client.sadd(taint_key, rule.tag)
            redis_client.expire(taint_key, 3600)

    return mcp_response.json()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)