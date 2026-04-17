#!/bin/sh
# Generate checksums.sha256 for all Lilith Zero release binaries.
#
# Usage: ./scripts/generate_checksums.sh <artifacts-dir>
#
# Called by CI (GitHub Actions) after building all platform binaries into
# the artifacts directory. The resulting file is uploaded as a release asset.
#
# Each line in the output follows the standard sha256sum(1) format:
#   <hex-digest>  <filename>

set -eu

ARTIFACTS_DIR="${1:-.}"

if [ ! -d "$ARTIFACTS_DIR" ]; then
    echo "Error: directory not found: $ARTIFACTS_DIR" >&2
    exit 1
fi

OUTPUT="$ARTIFACTS_DIR/checksums.sha256"

# Remove stale file if present.
rm -f "$OUTPUT"

echo "Generating SHA-256 checksums in $ARTIFACTS_DIR ..."

# sha256sum on Linux; shasum -a 256 on macOS.
if command -v sha256sum >/dev/null 2>&1; then
    SHA_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA_CMD="shasum -a 256"
else
    echo "Error: neither sha256sum nor shasum found" >&2
    exit 1
fi

# Hash all binary assets (skip directories and the output file itself).
found=0
for f in "$ARTIFACTS_DIR"/*; do
    base="$(basename "$f")"
    case "$base" in
        checksums.sha256 | *.json | *.md | *.txt) continue ;;
    esac
    if [ -f "$f" ]; then
        $SHA_CMD "$f" | sed "s|$ARTIFACTS_DIR/||" >> "$OUTPUT"
        found=$((found + 1))
    fi
done

if [ "$found" -eq 0 ]; then
    echo "Warning: no binary artifacts found in $ARTIFACTS_DIR" >&2
fi

echo "Generated $OUTPUT ($found file(s)):"
cat "$OUTPUT"
