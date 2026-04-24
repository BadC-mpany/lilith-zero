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
            x86_64)  TARGET="lilith-zero-macos-x86_64" ;;
            arm64)   TARGET="lilith-zero-macos-aarch64" ;;
            *)       echo "Unsupported macOS arch: $ARCH"; exit 1 ;;
        esac
        ;;
    linux)
        case "$ARCH" in
            x86_64)  TARGET="lilith-zero-linux-x86_64" ;;
            aarch64|arm64) TARGET="lilith-zero-linux-aarch64" ;;
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
CHECKSUM_URL="https://github.com/BadC-mpany/lilith-zero/releases/download/$LATEST_TAG/checksums.sha256"

# --- Install ---
echo "Downloading $LATEST_TAG -> $INSTALL_DIR/$BINARY_NAME..."
mkdir -p "$INSTALL_DIR"

# Download binary and checksum file to temp locations.
TMP_FILE=$(mktemp)
TMP_CHECKSUM=$(mktemp)

# Ensure temp files are removed on exit regardless of outcome.
cleanup() { rm -f "$TMP_FILE" "$TMP_CHECKSUM"; }
trap cleanup EXIT

curl -fL -o "$TMP_FILE" "$DOWNLOAD_URL"
curl -fL -o "$TMP_CHECKSUM" "$CHECKSUM_URL"

# --- Verify SHA-256 ---
echo "Verifying checksum..."

# sha256sum on Linux; shasum -a 256 on macOS.
if command -v sha256sum >/dev/null 2>&1; then
    SHA_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA_CMD="shasum -a 256"
else
    echo "Warning: cannot verify checksum (sha256sum/shasum not found). Continuing anyway."
    SHA_CMD=""
fi

if [ -n "$SHA_CMD" ]; then
    # Extract the expected digest for this target from the checksum file.
    EXPECTED=$(grep "$TARGET" "$TMP_CHECKSUM" | awk '{print $1}')
    if [ -z "$EXPECTED" ]; then
        echo "Error: checksum entry for '$TARGET' not found in checksums.sha256" >&2
        exit 1
    fi

    ACTUAL=$($SHA_CMD "$TMP_FILE" | awk '{print $1}')

    if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "" >&2
        echo "SECURITY ERROR: SHA-256 checksum mismatch!" >&2
        echo "  Expected : $EXPECTED" >&2
        echo "  Actual   : $ACTUAL" >&2
        echo "The downloaded binary may be corrupted or tampered with." >&2
        exit 1
    fi
    echo "Checksum OK: $ACTUAL"
fi

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
