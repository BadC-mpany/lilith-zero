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

import os
import sys
import platform
import logging
import urllib.request
import shutil
import stat
from typing import Optional

from .exceptions import SentinelConfigError

logger = logging.getLogger("sentinel_installer")

# GitHub Release Information
GITHUB_REPO = "peti12352/sentinel"
# If running mainly from pypi, we might default to "latest" or match the SDK version
# For now, let's look for "latest" to reduce friction
TAG_NAME = "latest"

def get_default_install_dir() -> str:
    """Return the platform-specific default installation directory."""
    home = os.path.expanduser("~")
    if platform.system() == "Windows":
        return os.path.join(home, ".sentinel", "bin")
    else:
        return os.path.join(home, ".local", "bin")

def _get_platform_asset_name() -> Optional[str]:
    """Determine the release asset name for the current platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "windows":
        return "sentinel.exe"
    elif system == "linux":
        # Check for aarch64?
        # Standard linux build in release.yml is x86_64
        return "sentinel"
    elif system == "darwin":
        if "arm" in machine or "aarch64" in machine:
            return "sentinel-macos-arm"
        else:
            return "sentinel-macos-x86"
    
    return None

def download_sentinel(interactive: bool = True) -> str:
    """
    Download and install the Sentinel binary from GitHub Releases.
    
    Args:
        interactive: If True, prompt the user before downloading.
        
    Returns:
        Path to the installed binary.
        
    Raises:
        SentinelConfigError: If installation fails or is declined.
    """
    install_dir = get_default_install_dir()
    os.makedirs(install_dir, exist_ok=True)
    
    asset_name = _get_platform_asset_name()
    if not asset_name:
        raise SentinelConfigError(f"Unsupported platform: {platform.system()} {platform.machine()}")

    # Target binary name (normalized)
    binary_name = "sentinel.exe" if platform.system() == "Windows" else "sentinel"
    target_path = os.path.join(install_dir, binary_name)

    if os.path.exists(target_path):
        # Already installed? Check version? For now, just return it.
        # Future: implement version check.
        return target_path

    # Construct URL (using 'latest' release for now to avoid hardcoding versions)
    # Note: GitHub 'latest' endpoint redirects to the tag.
    # Direct asset download: https://github.com/<owner>/<repo>/releases/latest/download/<asset>
    download_url = f"https://github.com/{GITHUB_REPO}/releases/latest/download/{asset_name}"

    msg = (
        f"Sentinel binary not found at {target_path}.\n"
        f"Would you like to automatically download it from:\n"
        f"{download_url}\n"
    )

    if interactive:
        print("="*60, file=sys.stderr)
        print(msg, file=sys.stderr)
        print("="*60, file=sys.stderr)
        response = input("Download now? [Y/n] ").strip().lower()
        if response and response != 'y':
            raise SentinelConfigError("Installation declined by user.")
    else:
        logger.info("Auto-downloading Sentinel binary...")

    try:
        logger.info(f"Downloading {download_url}...")
        with urllib.request.urlopen(download_url) as response, open(target_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        
        # Make executable on Unix
        if platform.system() != "Windows":
            st = os.stat(target_path)
            os.chmod(target_path, st.st_mode | stat.S_IEXEC)
            
        logger.info(f"Successfully installed Sentinel to {target_path}")
        return target_path
    except Exception as e:
        raise SentinelConfigError(f"Failed to download Sentinel binary: {e}")

# Backwards compatibility alias
install_sentinel = download_sentinel
