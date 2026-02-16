# Copyright 2026 BadCompany
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Lilith Binary Installer.

Helper module to bootstrap the Lilith binary if not found.
Currently provides detailed instructions, but structured to support
auto-download in future versions.
"""

import logging
import os
import platform
import shutil
import stat
import sys
import urllib.request

from .exceptions import LilithConfigError

_logger = logging.getLogger("lilith_zero.installer")

# GitHub Release Information
LILITH_VERSION = "0.1.1"
GITHUB_REPO = "BadC-mpany/lilith-zero"
# If running mainly from pypi, we might default to "latest" or match the SDK version
# For now, let's look for "latest" to reduce friction
TAG_NAME = "latest"


def get_default_install_dir() -> str:
    """Return the platform-specific default installation directory."""
    home = os.path.expanduser("~")
    if platform.system() == "Windows":
        return os.path.join(home, ".lilith_zero", "bin")
    else:
        return os.path.join(home, ".local", "bin")


def _get_platform_asset_name() -> str | None:
    """Determine the release asset name for the current platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "windows":
        return "lilith-zero.exe"
    elif system == "linux":
        return "lilith-zero"
    elif system == "darwin":
        if "arm" in machine or "aarch64" in machine:
            return "lilith-zero-macos-arm"
        else:
            return "lilith-zero-macos-x86"

    return None


def download_lilith(interactive: bool = True) -> str:
    """
    Download and install the Lilith binary from GitHub Releases.

    Args:
        interactive: If True, prompt the user before downloading.

    Returns:
        Path to the installed binary.

    Raises:
        LilithConfigError: If installation fails or is declined.
    """
    install_dir = get_default_install_dir()
    os.makedirs(install_dir, exist_ok=True)

    asset_name = _get_platform_asset_name()
    if not asset_name:
        raise LilithConfigError(
            f"Unsupported platform: {platform.system()} {platform.machine()}"
        )

    # Target binary name (normalized)
    binary_name = "lilith-zero.exe" if platform.system() == "Windows" else "lilith-zero"
    target_path = os.path.join(install_dir, binary_name)

    if os.path.exists(target_path):
        # Already installed? Check version? For now, just return it.
        # Future: implement version check.
        return target_path

    # Construct URL (using 'latest' release for now to avoid hardcoding versions)
    # Note: GitHub 'latest' endpoint redirects to the tag.
    # Direct asset download: https://github.com/<owner>/<repo>/releases/latest/download/<asset>
    download_url = (
        f"https://github.com/{GITHUB_REPO}/releases/latest/download/{asset_name}"
    )

    msg = (
        f"Lilith binary not found at {target_path}.\n"
        f"Would you like to automatically download it from:\n"
        f"{download_url}\n"
    )

    if interactive:
        print("=" * 60, file=sys.stderr)
        print(msg, file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        response = input("Download now? [Y/n] ").strip().lower()
        if response and response != "y":
            raise LilithConfigError("Installation declined by user.")
    else:
        _logger.info("Auto-downloading Lilith binary...")

    try:
        _logger.info(f"Downloading {download_url}...")
        # Rigour: add timeout to prevent indefinite hanging
        with (
            urllib.request.urlopen(download_url, timeout=30.0) as response,
            open(target_path, "wb") as out_file,
        ):
            shutil.copyfileobj(response, out_file)

        # Make executable on Unix
        if platform.system() != "Windows":
            st = os.stat(target_path)
            os.chmod(target_path, st.st_mode | stat.S_IEXEC)

        _logger.info(f"Successfully installed Lilith to {target_path}")
        return target_path
    except Exception as e:
        # Provide config_key for consistent structured error reporting
        raise LilithConfigError(
            f"Failed to download Lilith binary: {e}", config_key="binary"
        ) from e


# Aliases
download_Lilith = download_lilith
install_lilith = download_lilith
install_Lilith = download_lilith
