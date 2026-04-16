"""
Shared fixtures for example integration tests.

These tests require a built lilith-zero binary.  Set LILITH_ZERO_BINARY_PATH
or add lilith-zero to PATH before running.  Tests are automatically skipped if
the binary cannot be found.

Run:
    export LILITH_ZERO_BINARY_PATH=/path/to/lilith-zero
    python -m pytest examples/python/tests -v
"""

import os
import sys

import pytest

# Ensure the SDK is importable when running from the repo root.
_SDK_SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../sdk/src")
)
if _SDK_SRC not in sys.path:
    sys.path.insert(0, _SDK_SRC)


def pytest_configure(config):  # noqa: ARG001
    config.addinivalue_line(
        "markers",
        "integration: mark test as an end-to-end integration test requiring the binary",
    )


@pytest.fixture(scope="session")
def binary_path() -> str:
    """Resolve the lilith-zero binary; skip the test session if not found."""
    from lilith_zero.client import _find_binary  # type: ignore[attr-defined]
    from lilith_zero.exceptions import LilithConfigError

    try:
        return _find_binary()
    except LilithConfigError:
        pytest.skip(
            "lilith-zero binary not found — set LILITH_ZERO_BINARY_PATH or add to PATH"
        )


# Directories for each example set.
_EXAMPLES = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="session")
def minimal_policy() -> str:
    return os.path.join(_EXAMPLES, "minimal", "policy.yaml")


@pytest.fixture(scope="session")
def minimal_server() -> str:
    return os.path.join(_EXAMPLES, "minimal", "server.py")


@pytest.fixture(scope="session")
def advanced_policy() -> str:
    return os.path.join(_EXAMPLES, "advanced", "policy.yaml")


@pytest.fixture(scope="session")
def advanced_server() -> str:
    return os.path.join(_EXAMPLES, "advanced", "server.py")


@pytest.fixture(scope="session")
def calculator_policy() -> str:
    return os.path.join(_EXAMPLES, "fastmcp", "policy.yaml")


@pytest.fixture(scope="session")
def calculator_server() -> str:
    return os.path.join(_EXAMPLES, "fastmcp", "server.py")


@pytest.fixture(scope="session")
def agentic_policy() -> str:
    return os.path.join(_EXAMPLES, "langchain", "policy.yaml")


@pytest.fixture(scope="session")
def agentic_server() -> str:
    return os.path.join(_EXAMPLES, "langchain", "server.py")
