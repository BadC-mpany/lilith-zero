"""
Test-suite conftest.

Ensures the entire SDK test suite uses the correct Lilith binary — the one
compiled from this repo, not any stale system-wide install.  Sets
LILITH_ZERO_BINARY_PATH for the session so _find_binary() resolves to the
right artifact.

Priority:
  1. LILITH_ZERO_BINARY_PATH env var already set by caller (CI).
  2. Release build in this repo (lilith-zero/target/release/lilith-zero).
  3. Debug build in this repo (lilith-zero/target/debug/lilith-zero).
  4. Skip all tests that need the binary.
"""

import os
import sys

import pytest

_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

_CANDIDATES = [
    os.path.join(_REPO_ROOT, "lilith-zero", "target", "release", "lilith-zero"),
    os.path.join(_REPO_ROOT, "lilith-zero", "target", "debug", "lilith-zero"),
]
if sys.platform == "win32":
    _CANDIDATES = [p + ".exe" for p in _CANDIDATES]


def _resolve_binary() -> str | None:
    # Honour explicit override from caller.
    env = os.environ.get("LILITH_ZERO_BINARY_PATH", "")
    if env and os.path.isfile(env):
        return os.path.abspath(env)

    for candidate in _CANDIDATES:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)

    return None


_BINARY = _resolve_binary()

if _BINARY:
    os.environ["LILITH_ZERO_BINARY_PATH"] = _BINARY
    print(f"\n[conftest] Using Lilith binary: {_BINARY}", file=sys.stderr)
else:
    print(
        "\n[conftest] No compiled Lilith binary found — integration tests will be "
        "skipped.  Run `cargo build -p lilith-zero` first.",
        file=sys.stderr,
    )


@pytest.fixture(scope="session", autouse=True)
def require_binary() -> None:
    """Skip the entire session if the binary isn't available."""
    pass  # env var already set; individual tests use it via _find_binary()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip all tests that need a real binary when none is found."""
    if _BINARY:
        return
    skip = pytest.mark.skip(
        reason="No Lilith binary found — run `cargo build -p lilith-zero`"
    )
    for item in items:
        item.add_marker(skip)
