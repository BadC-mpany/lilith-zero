"""
Lilith SDK Exceptions.

Defines the hierarchy of errors raised by the Lilith middleware.
"""

from typing import Any, Optional, Dict

class LilithError(Exception):
    """Base class for all Lilith SDK errors."""
    pass

class LilithConfigError(LilithError):
    """Raised when configuration is invalid (e.g., missing binary)."""
    pass

class LilithConnectionError(LilithError):
    """Raised when the SDK fails to connect to the Lilith process."""
    pass

class LilithProcessError(LilithError):
    """Raised when the Lilith process behaves unexpectedly (crashes, strict IO)."""
    pass

class PolicyViolationError(LilithError):
    """Raised when a tool execution is blocked by the security policy."""
    def __init__(self, message: str, policy_details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.policy_details: Dict[str, Any] = policy_details or {}

class ToolExecutionError(LilithError):
    """Raised when the upstream tool itself fails (not a policy block)."""
    pass
