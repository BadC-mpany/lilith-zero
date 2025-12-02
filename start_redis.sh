#!/bin/bash
# Start Redis server for Sentinel
# Usage: ./start_redis.sh

set -e

echo "=========================================="
echo "Starting Redis Server for Sentinel"
echo "=========================================="

# Check if Redis is already running
if command -v redis-cli &> /dev/null 2>&1; then
    if redis-cli ping &> /dev/null 2>&1; then
        echo "✓ Redis is already running on localhost:6379"
        exit 0
    fi
fi

# Check if Redis is running as Windows service
if command -v sc &> /dev/null 2>&1; then
    if sc query Redis 2>/dev/null | grep -q "RUNNING"; then
        echo "✓ Redis is running as a Windows service"
        echo "  You can manage it with: sc stop Redis / sc start Redis"
        exit 0
    fi
fi

# Try to find redis-server in various locations
REDIS_CMD=""

# Check standard PATH first
if command -v redis-server &> /dev/null 2>&1; then
    REDIS_CMD="redis-server"
# Check Windows common installation paths (Git Bash format)
elif [ -f "/c/Program Files/Redis/redis-server.exe" ]; then
    REDIS_CMD="/c/Program Files/Redis/redis-server.exe"
elif [ -f "/c/redis/redis-server.exe" ]; then
    REDIS_CMD="/c/redis/redis-server.exe"
elif [ -f "C:/Program Files/Redis/redis-server.exe" ]; then
    REDIS_CMD="C:/Program Files/Redis/redis-server.exe"
# Check if running in WSL
elif command -v wsl &> /dev/null 2>&1; then
    if wsl which redis-server &> /dev/null 2>&1; then
        echo "Found Redis in WSL. Starting via WSL..."
        wsl redis-server --appendonly no --port 6379 &
        echo "✓ Redis started via WSL"
        exit 0
    fi
fi

# Check if Redis is available
if [ -z "$REDIS_CMD" ]; then
    echo "ERROR: redis-server not found!"
    echo ""
    echo "Please install Redis using one of these options:"
    echo ""
    echo "Option 1: Windows native (recommended)"
    echo "  Download from: https://github.com/microsoftarchive/redis/releases"
    echo "  Extract and add redis-server.exe to PATH or place in C:\\redis\\"
    echo ""
    echo "Option 2: WSL (if you have WSL installed)"
    echo "  wsl sudo apt-get update"
    echo "  wsl sudo apt-get install -y redis-server"
    echo "  Then Redis will be auto-detected"
    echo ""
    echo "Option 3: Chocolatey (if installed)"
    echo "  choco install redis-64"
    echo ""
    echo "Option 4: Linux/macOS"
    echo "  Ubuntu/Debian: sudo apt-get install redis-server"
    echo "  macOS:         brew install redis"
    exit 1
fi

# Start Redis with appropriate configuration
echo "Starting Redis on localhost:6379..."
echo "Using: $REDIS_CMD"
echo "Press Ctrl+C to stop Redis"
echo ""

# Handle Windows paths - convert to Windows format if needed
if [[ "$REDIS_CMD" == *".exe"* ]]; then
    # Windows executable - run directly
    "$REDIS_CMD" --appendonly no --port 6379
else
    # Unix-style command
    $REDIS_CMD --appendonly no --port 6379
fi

