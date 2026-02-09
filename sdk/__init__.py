# lilith_zero/__init__.py
# Root package initialization for the SDK.

from .lilith_zero.client import Lilith
from .lilith_zero.exceptions import (
    LilithError,
    LilithConfigError,
    LilithConnectionError,
    LilithProcessError,
    PolicyViolationError,
)

__all__ = [
    "Lilith",
    "LilithError",
    "LilithConfigError",
    "LilithConnectionError",
    "LilithProcessError",
    "PolicyViolationError",
]
