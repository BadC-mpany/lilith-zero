"""
Sentinel SDK Constants - Single source of truth for all configuration values.

This module centralizes all magic numbers, version strings, and configuration
defaults to ensure consistency and maintainability across the SDK.
"""
import platform

# =============================================================================
# Version Information
# =============================================================================

__version__ = "0.1.0"

# =============================================================================
# MCP Protocol Constants
# =============================================================================

MCP_PROTOCOL_VERSION = "2024-11-05"
SDK_NAME = "sentinel-sdk"

# =============================================================================
# Timeout Configuration (seconds)
# =============================================================================

SESSION_TIMEOUT_SEC = 5.0
SESSION_POLL_INTERVAL_SEC = 0.1
SESSION_TIMEOUT_ITERATIONS = int(SESSION_TIMEOUT_SEC / SESSION_POLL_INTERVAL_SEC)

# =============================================================================
# Binary Discovery
# =============================================================================

BINARY_NAME_WINDOWS = "sentinel-interceptor.exe"
BINARY_NAME_UNIX = "sentinel-interceptor"

def get_binary_name() -> str:
    """Returns the appropriate binary name for the current platform."""
    return BINARY_NAME_WINDOWS if platform.system() == "Windows" else BINARY_NAME_UNIX

# Environment variable names
ENV_BINARY_PATH = "SENTINEL_BINARY_PATH"
ENV_POLICY_PATH = "POLICIES_YAML_PATH"
ENV_LOG_LEVEL = "LOG_LEVEL"
ENV_SPOTLIGHTING = "SENTINEL_SPOTLIGHTING"
ENV_STRICT_TAINT = "SENTINEL_STRICT_TAINT"
ENV_SESSION_VALIDATION = "SENTINEL_SESSION_VALIDATION"

# Relative paths to search for binary (in order of preference)
BINARY_SEARCH_PATHS = [
    "sentinel_middleware/target/release/",
    "target/release/",
    "./",
]

# =============================================================================
# Security Level Configuration
# =============================================================================

SECURITY_LEVEL_LOW = "low"
SECURITY_LEVEL_MEDIUM = "medium"
SECURITY_LEVEL_HIGH = "high"
DEFAULT_SECURITY_LEVEL = SECURITY_LEVEL_HIGH

SECURITY_LEVEL_CONFIG = {
    SECURITY_LEVEL_LOW: {
        "spotlighting": False,
        "strict_taint": False,
        "session_validation": False,
    },
    SECURITY_LEVEL_MEDIUM: {
        "spotlighting": True,
        "strict_taint": False,
        "session_validation": True,
    },
    SECURITY_LEVEL_HIGH: {
        "spotlighting": True,
        "strict_taint": True,
        "session_validation": True,
    },
}

# =============================================================================
# Logging
# =============================================================================

DEFAULT_LOG_LEVEL = "info"
LOG_FORMAT_JSON = "json"
LOG_FORMAT_TEXT = "text"
DEFAULT_LOG_FORMAT = LOG_FORMAT_TEXT
