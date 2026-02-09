"""
Lilith SDK - Secure MCP Middleware for AI Agents.

Provides security controls for Model Context Protocol tool servers including:
- Session integrity (HMAC-signed session IDs)
- Policy enforcement (static rules, dynamic taint tracking)
- Process isolation
"""

from .client import Lilith
from .exceptions import (
    LilithError,
    LilithConfigError,
    LilithConnectionError,
    LilithProcessError,
    PolicyViolationError,
)

__version__ = "0.1.0"
__all__ = [
    "Lilith",
    "LilithError",
    "LilithConfigError",
    "LilithConnectionError",
    "LilithProcessError",
    "PolicyViolationError",
    "__version__"
]
