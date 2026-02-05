"""
Sentinel SDK Exceptions.

Defines the hierarchy of errors raised by the Sentinel middleware.
"""

from typing import Any, Optional, Dict

class SentinelError(Exception):
    """Base class for all Sentinel SDK errors."""
    pass

class SentinelConfigError(SentinelError):
    """Raised when configuration is invalid (e.g., missing binary)."""
    pass

class SentinelConnectionError(SentinelError):
    """Raised when the SDK fails to connect to the Sentinel process."""
    pass

class SentinelProcessError(SentinelError):
    """Raised when the Sentinel process behaves unexpectedly (crashes, strict IO)."""
    pass

class PolicyViolationError(SentinelError):
    """Raised when a tool execution is blocked by the security policy."""
    def __init__(self, message: str, policy_details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.policy_details: Dict[str, Any] = policy_details or {}

class ToolExecutionError(SentinelError):
    """Raised when the upstream tool itself fails (not a policy block)."""
    pass
