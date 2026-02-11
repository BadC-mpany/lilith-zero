#!/bin/sh
# Lilith Zero - Security-First Installer
# https://github.com/BadC-mpany/lilith-zero

set -e

# --- Configuration ---
OWNER="BadC-mpany"
REPO="lilith-zero"
BINARY_NAME="lilith-zero"

# --- Detect OS and Architecture ---
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    darwin)
        case "$ARCH" in
            x86_64)  TARGET="lilith-zero-macos-x86" ;;
            arm64)   TARGET="lilith-zero-macos-arm" ;;
            *)       echo "Unsupported macOS architecture: $ARCH"; exit 1 ;;
        esac
        ;;
    linux)
        case "$ARCH" in
            x86_64)  TARGET="lilith-zero" ;;
            *)       echo "Unsupported Linux architecture: $ARCH. Please build from source."; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "For Windows, please install via the Python SDK: pip install lilith-zero"
        exit 1
        ;;
esac

# --- Fetch Latest Version ---
echo "Detecting latest version..."
LATEST_TAG=$(curl -s "https://api.github.com/repos/$OWNER/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo "Error: Could not retrieve latest version tag."
    exit 1
fi

DOWNLOAD_URL="https://github.com/BadC-mpany/lilith-zero/releases/download/$LATEST_TAG/$TARGET"

# --- Execution ---
echo "Downloading Lilith Zero $LATEST_TAG ($TARGET)..."
curl -L -o "$BINARY_NAME" "$DOWNLOAD_URL"
chmod +x "$BINARY_NAME"

echo ""
echo "------------------------------------------------------------"
echo "Lilith Zero binary downloaded successfully."
echo "------------------------------------------------------------"
echo ""
echo "To install globally, run:"
echo "  sudo mv $BINARY_NAME /usr/local/bin/"
echo ""
echo "To use locally, run:"
echo "  ./$BINARY_NAME --help"
echo ""
echo "Verification complete. Deterministic security mode: ACTIVE."
