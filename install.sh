#!/bin/sh
# Lilith Zero - Professional Installer
# https://github.com/BadC-mpany/lilith-zero

set -e

# --- Configuration ---
OWNER="BadC-mpany"
REPO="lilith-zero"
BINARY_NAME="lilith-zero"
INSTALL_DIR="$HOME/.local/bin"

# --- Detect OS and Architecture ---
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    darwin)
        case "$ARCH" in
            x86_64)  TARGET="lilith-zero-macos-x86" ;;
            arm64)   TARGET="lilith-zero-macos-arm" ;;
            *)       echo "Are you running on a toaster? Unsupported macOS arch: $ARCH"; exit 1 ;;
        esac
        ;;
    linux)
        case "$ARCH" in
            x86_64)  TARGET="lilith-zero" ;;
            *)       echo "Unsupported Linux arch: $ARCH. Please build from source."; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# --- Fetch Latest ---
echo "Lilith Zero | Initializing..."
LATEST_JSON=$(curl -s "https://api.github.com/repos/$OWNER/$REPO/releases/latest")
LATEST_TAG=$(echo "$LATEST_JSON" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo "Error: Unable to resolve latest version. Rate limit?"
    exit 1
fi

DOWNLOAD_URL="https://github.com/BadC-mpany/lilith-zero/releases/download/$LATEST_TAG/$TARGET"

# --- Install ---
echo "Downloading $LATEST_TAG -> $INSTALL_DIR/$BINARY_NAME..."
mkdir -p "$INSTALL_DIR"

# Download to temp file first
TMP_FILE=$(mktemp)
curl -L -o "$TMP_FILE" "$DOWNLOAD_URL"
chmod +x "$TMP_FILE"
mv "$TMP_FILE" "$INSTALL_DIR/$BINARY_NAME"

echo ""
echo "------------------------------------------------------------"
echo "  INSTALLED: $INSTALL_DIR/$BINARY_NAME"
echo "------------------------------------------------------------"
echo ""

# Check PATH
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "WARNING: $INSTALL_DIR is not in your PATH."
       echo "Add this to your shell profile (.zshrc/.bashrc):"
       echo "  export PATH=\"\$HOME/.local/bin:\$PATH\"" 
       echo "" ;;
esac

$INSTALL_DIR/$BINARY_NAME --version
