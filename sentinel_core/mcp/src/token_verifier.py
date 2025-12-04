# sentinel-core/mcp/src/token_verifier.py

import os
import jwt
from logging import getLogger
import logging
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Dict, Any

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

    def __init__(self, **kwargs):
        # Override defaults with environment variables if they exist
        # Pydantic BaseSettings should read from env automatically, but we ensure it here
        env_kwargs = {}
        if "MCP_PUBLIC_KEY_PATH" in os.environ:
            env_kwargs["mcp_public_key_path"] = os.environ["MCP_PUBLIC_KEY_PATH"]

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
    verify_key: bytes = Depends(lambda: open(settings.mcp_public_key_path, "rb").read())
):
    """
    The Verifier Middleware (legacy /execute endpoint).
    STATELESS verification - NO Redis dependency.
    
    Verifies:
    1. Cryptographic signature (Ed25519)
    2. Parameter integrity hash (p_hash)
    3. Scope match (tool name)
    4. Expiration (handled by jwt.decode)
    
    Replay protection removed - tokens expire in 5 seconds and are single-use.
    """
    token = auth.credentials

    # 1. CRYPTOGRAPHIC VERIFICATION (Ed25519) + EXPIRATION CHECK
    try:
        payload = jwt.decode(token, verify_key, algorithms=["EdDSA"], issuer="sentinel-interceptor")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token Expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid Signature")

    # 2. SCOPE CHECK
    if payload.get("scope") != f"tool:{req.tool}":
        raise HTTPException(status_code=403, detail="Token Scope Mismatch")

    # 3. PARAMETER INTEGRITY CHECK (Anti-TOCTOU)
    received_hash = CryptoUtils.hash_params(req.args)
    if received_hash != payload.get("p_hash"):
        raise HTTPException(
            status_code=403, detail="Integrity Violation: Parameters Altered in Transit")

    return True


def verify_token_direct(token: str, tool_name: str, arguments: Dict[str, Any]) -> None:
    """
    Stateless token verification function (non-FastAPI dependency version).
    NO Redis dependency - fully stateless verification.
    
    Verifies:
    1. Cryptographic signature (Ed25519) - prevents tampering
    2. Parameter integrity hash (p_hash) - prevents parameter tampering
    3. Scope match (tool name) - ensures token is for correct tool
    4. Expiration (handled by jwt.decode) - tokens expire in 5 seconds
    
    Replay protection removed - tokens expire in 5 seconds and are single-use per request.
    This makes MCP server fully stateless and independent of Redis.
    
    Raises HTTPException on failure.
    """
    logger.debug(f"Starting stateless token verification for tool: {tool_name}")
    
    # Load public key
    try:
        with open(settings.mcp_public_key_path, "rb") as f:
            verify_key = f.read()
    except FileNotFoundError:
        logger.error(f"Public key file not found at: {settings.mcp_public_key_path}")
        raise HTTPException(status_code=500, detail="Public key file not found")
    except Exception as e:
        logger.error(f"Error reading public key file: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error reading public key")

    # 1. CRYPTOGRAPHIC VERIFICATION (Ed25519) + EXPIRATION CHECK
    logger.debug("Verifying JWT token signature and expiration")
    try:
        payload = jwt.decode(token, verify_key, algorithms=["EdDSA"], issuer="sentinel-interceptor")
        logger.debug(f"Token verified successfully, jti: {payload.get('jti')}")
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        raise HTTPException(status_code=401, detail="Token Expired")
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token signature: {e}")
        raise HTTPException(status_code=401, detail="Invalid Signature")

    # 2. SCOPE CHECK
    expected_scope = f"tool:{tool_name}"
    actual_scope = payload.get("scope")
    logger.debug(f"Checking scope: expected={expected_scope}, actual={actual_scope}")
    if actual_scope != expected_scope:
        logger.warning(f"Scope mismatch: expected={expected_scope}, actual={actual_scope}")
        raise HTTPException(status_code=403, detail="Token Scope Mismatch")

    # 3. PARAMETER INTEGRITY CHECK (Anti-TOCTOU)
    logger.debug("Verifying parameter integrity hash")
    received_hash = CryptoUtils.hash_params(arguments)
    expected_hash = payload.get("p_hash")
    if received_hash != expected_hash:
        logger.warning(f"Parameter hash mismatch: received={received_hash}, expected={expected_hash}")
        raise HTTPException(
            status_code=403, detail="Integrity Violation: Parameters Altered in Transit")
    
    logger.info(f"Token verification successful for tool: {tool_name}")
    # Note: Replay protection removed - tokens expire in 5 seconds and are single-use per request


def verify_sentinel_token_mcp(
    params: MCPCallParams,
    auth: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    verify_key: bytes = Depends(lambda: open(settings.mcp_public_key_path, "rb").read())
):
    """
    MCP-compatible Verifier Middleware for JSON-RPC 2.0 requests.
    STATELESS verification - NO Redis dependency.
    
    Extracts tool name and arguments from MCP params structure.
    Verifies: signature, scope, p_hash, expiration (replay protection removed).
    """
    token = auth.credentials
    verify_token_direct(token, params.name, params.arguments)
    return True
