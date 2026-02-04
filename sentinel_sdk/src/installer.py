"""
Sentinel Binary Installer.

Helper module to bootstrap the Sentinel binary if not found.
Currently provides detailed instructions, but structured to support
auto-download in future versions.
"""

import os
import sys
import platform
import logging

from .exceptions import SentinelConfigError

logger = logging.getLogger("sentinel_installer")

def get_default_install_dir() -> str:
    """Return the platform-specific default installation directory."""
    home = os.path.expanduser("~")
    if platform.system() == "Windows":
        return os.path.join(home, ".sentinel", "bin")
    else:
        return os.path.join(home, ".local", "bin")

def install_sentinel(interactive: bool = True) -> str:
    """
    Attempt to install or guide the user to install the Sentinel binary.
    
    Args:
        interactive: If True, may prompt the user (CLI only).
        
    Returns:
        Path to the installed binary.
        
    Raises:
        SentinelConfigError: If installation fails or is declined.
    """
    # For v0.2.0, we prioritize safety and just guide the user.
    # Future: Download from GitHub Releases based on platform/arch.
    
    msg = (
        "Sentinel binary not found!\n\n"
        "To fix this:\n"
        "1. Download the latest release from: https://github.com/google-deepmind/sentinel/releases\n"
        "2. Extract 'sentinel' (or 'sentinel.exe') to a folder in your PATH.\n"
        "   OR set SENTINEL_BINARY_PATH env var to the full path.\n\n"
        "Development Mode:\n"
        "   cargo build --release\n"
        "   export SENTINEL_BINARY_PATH=./target/release/sentinel"
    )
    
    if interactive:
        print("="*60, file=sys.stderr)
        print(msg, file=sys.stderr)
        print("="*60, file=sys.stderr)
        
    raise SentinelConfigError("Sentinel binary not found. See logs for installation instructions.")
