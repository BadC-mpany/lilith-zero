# sentinel_sdk/__init__.py
# Compatibility shim so "import sentinel_sdk" works when the repo root is on sys.path.
# Re-export the real package located at sentinel_sdk/sentinel_sdk.

from .sentinel_sdk import (  # noqa: F401
    Sentinel,
    SentinelError,
    SentinelConfigError,
    SentinelConnectionError,
    SentinelProcessError,
    PolicyViolationError,
)

__all__ = [
    "Sentinel",
    "SentinelError",
    "SentinelConfigError",
    "SentinelConnectionError",
    "SentinelProcessError",
    "PolicyViolationError",
]
