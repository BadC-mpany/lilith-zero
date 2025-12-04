# sentinel-core/mcp/src/token_verifier.py

import os
import time
import jwt
import redis
from logging import getLogger
import logging
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Dict, Any, Optional

import sys
from pathlib import Path
# Add shared Python src to path for crypto_utils
# From sentinel_core/mcp/src/token_verifier.py -> go up 3 levels to sentinel_core -> shared/python/src
# Use resolve() to get absolute path
_current_file = Path(__file__).resolve()
shared_src_path = _current_file.parent.parent.parent / "shared" / "python" / "src"
if str(shared_src_path) not in sys.path:
    sys.path.insert(0, str(shared_src_path))
from crypto_utils import CryptoUtils
logger = getLogger(__name__)
logger.setLevel(logging.INFO)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore', env_prefix='')

    # Default to Windows/local path, override with MCP_PUBLIC_KEY_PATH env var
    # Use resolve() to get absolute path
    mcp_public_key_path: str = str(Path(__file__).resolve().parent.parent / "keys" / "interceptor_public_key.pem")
    redis_host: str = "localhost"  # Default to localhost for non-Docker environments
    redis_port: int = 6379
    redis_db: int = 1

    def __init__(self, **kwargs):
        # Override defaults with environment variables if they exist
        # Pydantic BaseSettings should read from env automatically, but we ensure it here
        env_kwargs = {}
        if "MCP_PUBLIC_KEY_PATH" in os.environ:
            env_kwargs["mcp_public_key_path"] = os.environ["MCP_PUBLIC_KEY_PATH"]
        if "REDIS_HOST" in os.environ:
            env_kwargs["redis_host"] = os.environ["REDIS_HOST"]
        if "REDIS_PORT" in os.environ:
            env_kwargs["redis_port"] = int(os.environ["REDIS_PORT"])
        if "REDIS_DB" in os.environ:
            env_kwargs["redis_db"] = int(os.environ["REDIS_DB"])

        # Merge environment variables with kwargs
        merged_kwargs = {**env_kwargs, **kwargs}
        super().__init__(**merged_kwargs)


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
    try:
        redis_cache = get_redis_connection()
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Redis connection failed")

    try:
        with open(settings.mcp_public_key_path, "rb") as f:
            verify_key = f.read()
    except FileNotFoundError:
        logger.error(f"Public key file not found at: {settings.mcp_public_key_path}")
        raise HTTPException(status_code=500, detail="Public key file not found")
    except Exception as e:
        logger.error(f"Error reading public key file: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error reading public key")

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
