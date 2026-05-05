#!/bin/bash

# Check if session files exist on Azure deployment
# This script checks ~/.lilith/sessions for any session files

SESSION_DIR="$HOME/.lilith/sessions"

echo "Checking for session files at: $SESSION_DIR"
echo ""

if [ -d "$SESSION_DIR" ]; then
    echo "✓ Session directory exists"
    echo ""
    echo "Session files found:"
    ls -lah "$SESSION_DIR" 2>/dev/null || echo "  (No files or directory not readable)"
    echo ""
    echo "Count: $(find "$SESSION_DIR" -type f -name "*.json" 2>/dev/null | wc -l) files"
    echo ""
    echo "Recent files (within last hour):"
    find "$SESSION_DIR" -name "*.json" -mmin -60 2>/dev/null || echo "  (None)"
else
    echo "✗ Session directory does NOT exist"
    echo ""
    echo "Creating it and testing permissions..."
    mkdir -p "$SESSION_DIR" 2>&1

    if [ $? -eq 0 ]; then
        echo "✓ Successfully created directory"
        touch "$SESSION_DIR/test.json" 2>&1 && rm "$SESSION_DIR/test.json" 2>&1
        if [ $? -eq 0 ]; then
            echo "✓ Directory is writable"
        else
            echo "✗ Directory is NOT writable"
        fi
    else
        echo "✗ Failed to create directory"
    fi
fi
