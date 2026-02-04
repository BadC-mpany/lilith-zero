"""
Sentinel SDK - Secure MCP Middleware for AI Agents.

Provides security controls for Model Context Protocol tool servers including:
- Session integrity (HMAC-signed session IDs)
- Policy enforcement (static rules, dynamic taint tracking)
- Process isolation
"""

from .client import Sentinel
from .exceptions import (
    SentinelError,
    SentinelConfigError,
    SentinelConnectionError,
    SentinelProcessError,
    PolicyViolationError,
)

__version__ = "0.1.0"
__all__ = [
    "Sentinel",
    "SentinelError",
    "SentinelConfigError",
    "SentinelConnectionError",
    "SentinelProcessError",
    "PolicyViolationError",
    "__version__"
]
