"""
Sentinel SDK - Secure MCP Middleware for AI Agents.

Provides security controls for Model Context Protocol tool servers including:
- Session integrity (HMAC-signed session IDs)
- Policy enforcement (static rules, dynamic taint tracking)
- Spotlighting (prompt injection defense)
- Process isolation
"""
from typing import List, Dict, Optional, Union
import os
import shutil

from .src.sentinel_sdk import Sentinel
from .src.constants import (
    __version__,
    SECURITY_LEVEL_CONFIG,
    SECURITY_LEVEL_LOW,
    SECURITY_LEVEL_MEDIUM,
    SECURITY_LEVEL_HIGH,
    DEFAULT_SECURITY_LEVEL,
    ENV_BINARY_PATH,
    ENV_POLICY_PATH,
    ENV_LOG_LEVEL,
    ENV_SPOTLIGHTING,
    ENV_STRICT_TAINT,
    ENV_SESSION_VALIDATION,
    ENV_MCP_VERSION,
    DEFAULT_LOG_LEVEL,
    BINARY_SEARCH_PATHS,
    get_binary_name,
)
from .src.prompts import get_default_prompt, get_full_prompt

__all__ = [
    "Sentinel",
    "__version__",
    "SECURITY_LEVEL_LOW",
    "SECURITY_LEVEL_MEDIUM", 
    "SECURITY_LEVEL_HIGH",
    "ENV_BINARY_PATH",
    "ENV_POLICY_PATH",
]

def _find_binary() -> Optional[str]:
    """
    Discover the Sentinel binary using multiple strategies.
    
    Order of preference:
    1. SENTINEL_BINARY_PATH environment variable
    2. System PATH
    3. Relative search paths (for development)
    """
    # 1. Environment variable
    env_path = os.getenv(ENV_BINARY_PATH)
    if env_path and os.path.exists(env_path):
        return os.path.abspath(env_path)
    
    # 2. System PATH
    binary_name = get_binary_name()
    path_binary = shutil.which(binary_name)
    if path_binary:
        return path_binary
    
    # 3. Relative search paths
    for search_path in BINARY_SEARCH_PATHS:
        candidate = os.path.join(search_path, binary_name)
        if os.path.exists(candidate):
            return os.path.abspath(candidate)
    
    return None

class SentinelHelper:
    """
    Static helper for Sentinel MCP Middleware.
    """
    
    @staticmethod
    def start(
        upstream: str,
        policy: Optional[str] = None,
        security_level: str = DEFAULT_SECURITY_LEVEL,
        binary_path: Optional[str] = None,
        mcp_version: Optional[str] = None,
        # New Sandbox Flags
        language_profile: Optional[str] = None,
        allow_read: Optional[List[str]] = None,
        allow_write: Optional[List[str]] = None,
        allow_net: bool = False,
        allow_env: Optional[List[str]] = None,
        dry_run: bool = False,
        skip_handshake: bool = False
    ) -> Sentinel:
        """
        Start a Sentinel-protected MCP session with optional sandboxing.
        """
        # Parse upstream command
        parts = upstream.split()
        if len(parts) < 1:
            raise ValueError("upstream must contain at least a command")
        
        upstream_cmd = parts[0]
        upstream_args = parts[1:] if len(parts) > 1 else []
        
        # Find binary
        resolved_binary = binary_path or _find_binary()
        if resolved_binary is None:
            raise FileNotFoundError(
                f"Could not find sentinel binary."
            )
        
        # Resolve policy path
        policy_path = os.path.abspath(policy) if policy else None
        
        # Apply security level settings via environment
        level_config = SECURITY_LEVEL_CONFIG.get(security_level, SECURITY_LEVEL_CONFIG[DEFAULT_SECURITY_LEVEL])
        os.environ[ENV_SPOTLIGHTING] = "1" if level_config["spotlighting"] else "0"
        os.environ[ENV_STRICT_TAINT] = "1" if level_config["strict_taint"] else "0"
        os.environ[ENV_SESSION_VALIDATION] = "1" if level_config["session_validation"] else "0"
        
        if mcp_version:
             os.environ[ENV_MCP_VERSION] = mcp_version
        
        return Sentinel(
            upstream_cmd=upstream_cmd,
            upstream_args=upstream_args,
            binary_path=resolved_binary,
            policy_path=policy_path,
            mcp_version=mcp_version,
            language_profile=language_profile,
            allow_read=allow_read,
            allow_write=allow_write,
            allow_net=allow_net,
            allow_env=allow_env,
            dry_run=dry_run,
            skip_handshake=skip_handshake
        )
    
    @staticmethod
    def wrap_command(
        upstream_cmd: str,
        upstream_args: List[str],
        sentinel_path: Optional[str] = None,
        policies_path: Optional[str] = None,
        log_level: str = DEFAULT_LOG_LEVEL
    ) -> Dict[str, Union[str, List[str], Dict[str, str]]]:
        """
        Generates the command to run an MCP server through Sentinel.
        
        Returns:
            A dictionary compatible with MCP configuration.
        """
        resolved_sentinel = sentinel_path or _find_binary() or get_binary_name()
        
        args = ["--upstream-cmd", upstream_cmd]
        if policies_path:
            args.extend(["--policy", os.path.abspath(policies_path)])
        args.append("--")
        args.extend(upstream_args)
        
        env = os.environ.copy()
        env[ENV_LOG_LEVEL] = log_level
        
        return {
            "command": resolved_sentinel,
            "args": args,
            "env": env
        }

    @staticmethod
    def get_system_prompt() -> str:
        """Returns system prompt for LLM awareness of Spotlighting."""
        return get_default_prompt()
    
    @staticmethod
    def get_full_system_prompt() -> str:
        """Returns comprehensive security prompt."""
        return get_full_prompt()

    @staticmethod
    def get_version() -> str:
        """Returns the SDK version."""
        return __version__
