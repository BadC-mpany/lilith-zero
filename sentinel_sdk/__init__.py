"""
Sentinel SDK - Secure MCP Middleware for AI Agents.

Provides security controls for Model Context Protocol tool servers including:
- Session integrity (HMAC-signed session IDs)
- Policy enforcement (static rules, dynamic taint tracking)
- Spotlighting (prompt injection defense)
- Process isolation (Windows AppContainer, Linux namespaces)

Example:
    from sentinel_sdk import Sentinel

    async with Sentinel("python mcp_server.py", policy="policy.yaml") as s:
        tools = await s.list_tools()
        result = await s.call_tool("my_tool", {"arg": "value"})

Copyright 2024 Google DeepMind. All Rights Reserved.
"""

from .src.sentinel_sdk import Sentinel

__version__ = "0.2.0"
__all__ = ["Sentinel", "__version__"]
