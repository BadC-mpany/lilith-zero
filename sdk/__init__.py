# lilith_zero/__init__.py
# Compatibility shim so "import lilith_zero" works when the repo root is on sys.path.
# Re-export the real package located at lilith_zero/lilith_zero.

from .lilith_zero import (  # noqa: F401
    Lilith,
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
