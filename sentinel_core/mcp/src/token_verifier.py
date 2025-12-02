# sentinel-core/mcp/src/token_verifier.py

import os
import time
import jwt
import redis
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Dict, Any, Optional

from crypto_utils import CryptoUtils


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    mcp_public_key_path: str = "/app/secrets/mcp_public.pem"
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_db: int = 1


settings = Settings()


class ToolRequest(BaseModel):
    tool: str
    args: Dict[str, Any]


class MCPCallParams(BaseModel):
    """MCP JSON-RPC 2.0 params structure for tools/call."""
    name: str
    arguments: Dict[str, Any]


def verify_sentinel_token(
    req: ToolRequest,
    auth: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    redis_cache: redis.Redis = Depends(lambda: redis.Redis(host=settings.redis_host, port=settings.redis_port, db=settings.redis_db)),
    verify_key: bytes = Depends(lambda: open(settings.mcp_public_key_path, "rb").read())
):
    """
    The Verifier Middleware (legacy /execute endpoint).
    This logic enforces the 'Zero Trust' boundary.
    It trusts the Token Signature, NOT the caller IP.
    """
    token = auth.credentials

    # 1. CRYPTOGRAPHIC VERIFICATION (Ed25519)
    try:
        payload = jwt.decode(token, verify_key, algorithms=["EdDSA"], issuer="sentinel-interceptor")
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


# Redis connection pool for reuse
_redis_pool: Optional[redis.ConnectionPool] = None

def get_redis_connection() -> redis.Redis:
    """Get a Redis connection from the pool."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = redis.ConnectionPool(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db,
            decode_responses=False,
            socket_connect_timeout=2,
            socket_timeout=2
        )
    return redis.Redis(connection_pool=_redis_pool)


def verify_token_direct(token: str, tool_name: str, arguments: Dict[str, Any]) -> None:
    """
    Direct token verification function (non-FastAPI dependency version).
    Raises HTTPException on failure.
    """
    redis_cache = get_redis_connection()
    
    with open(settings.mcp_public_key_path, "rb") as f:
        verify_key = f.read()

    # 1. CRYPTOGRAPHIC VERIFICATION (Ed25519)
    try:
        payload = jwt.decode(token, verify_key, algorithms=["EdDSA"], issuer="sentinel-interceptor")
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
    if payload.get("scope") != f"tool:{tool_name}":
        raise HTTPException(status_code=403, detail="Token Scope Mismatch")

    # 4. PARAMETER BINDING (Anti-TOCTOU)
    received_hash = CryptoUtils.hash_params(arguments)
    if received_hash != payload.get("p_hash"):
        raise HTTPException(
            status_code=403, detail="Integrity Violation: Parameters Altered in Transit")


def verify_sentinel_token_mcp(
    params: MCPCallParams,
    auth: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    redis_cache: redis.Redis = Depends(lambda: redis.Redis(host=settings.redis_host, port=settings.redis_port, db=settings.redis_db)),
    verify_key: bytes = Depends(lambda: open(settings.mcp_public_key_path, "rb").read())
):
    """
    MCP-compatible Verifier Middleware for JSON-RPC 2.0 requests.
    Extracts tool name and arguments from MCP params structure.
    Maintains all existing security checks (signature, nonce, scope, p_hash).
    """
    token = auth.credentials
    verify_token_direct(token, params.name, params.arguments)
    return True
