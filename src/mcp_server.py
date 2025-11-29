import time
import jwt
import redis
import os
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Dict, Any
from .sentinel_core import CryptoUtils


# --- CONFIGURATION CLASS ---
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    mcp_public_key_path: str = "secrets/mcp_public.pem"
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 1  # db=1 for Replay Cache


# --- GLOBAL CONFIGURATION LOAD ---
settings = Settings()

try:
    with open(settings.mcp_public_key_path, "rb") as f:
        VERIFY_KEY = f.read()
except FileNotFoundError:
    raise RuntimeError(
        f"Public key not found at {settings.mcp_public_key_path}. "
        "Please run keygen.py first!"
    )

app = FastAPI(title="Secure MCP Resource (Zone C)")
security = HTTPBearer()
redis_cache = redis.Redis(
    host=settings.redis_host, port=settings.redis_port, db=settings.redis_db
)


class ToolRequest(BaseModel):
    tool: str
    args: Dict[str, Any]


def verify_sentinel_token(
    req: ToolRequest,
    auth: HTTPAuthorizationCredentials = Depends(security)
):
    """
    The Verifier Middleware.
    This logic enforces the 'Zero Trust' boundary.
    It trusts the Token Signature, NOT the caller IP.
    """
    token = auth.credentials

    # 1. CRYPTOGRAPHIC VERIFICATION (Ed25519)
    try:
        payload = jwt.decode(token, VERIFY_KEY, algorithms=[
                             "EdDSA"], issuer="sentinel-interceptor")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token Expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid Signature")

    # 2. REPLAY PROTECTION (Nonce Check)
    jti = payload.get("jti")
    if redis_cache.exists(f"nonce:{jti}"):
        raise HTTPException(status_code=403, detail="Replay Attack Detected")

    # Burn the nonce
    ttl = int(payload["exp"] - time.time())
    if ttl > 0:
        redis_cache.setex(f"nonce:{jti}", ttl, "used")

    # 3. SCOPE CHECK
    if payload.get("scope") != f"tool:{req.tool}":
        raise HTTPException(status_code=403, detail="Token Scope Mismatch")

    # 4. PARAMETER BINDING (Anti-TOCTOU)
    received_hash = CryptoUtils.hash_params(req.args)
    if received_hash != payload.get("p_hash"):
        raise HTTPException(
            status_code=403, detail="Integrity Violation: Parameters Altered in Transit")

    return True


@app.post("/execute")
def execute_tool(req: ToolRequest, authorized: bool = Depends(verify_sentinel_token)):
    """
    The actual tool logic. This only runs if the Verifier passes.
    """
    print(f"[MCP] Executing {req.tool} with {req.args}")

    if req.tool == "read_file":
        # Simulate reading a private file
        return {"status": "success", "data": "CONFIDENTIAL: Project Apollo Launch Codes..."}

    elif req.tool == "web_search":
        # Simulate web search
        return {"status": "success", "data": "Search Results for: " + str(req.args)}

    elif req.tool == "delete_db":
        return {"status": "success", "data": "Database Deleted"}

    return {"status": "error", "message": "Tool not found"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)