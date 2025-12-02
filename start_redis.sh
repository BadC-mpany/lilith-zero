#!/bin/bash
# Start Redis server for Sentinel
# Usage: ./start_redis.sh

set -e

echo "=========================================="
echo "Starting Redis Server for Sentinel"
echo "=========================================="

# Check if redis-server is installed
if ! command -v redis-server &> /dev/null; then
    echo "ERROR: redis-server not found!"
    echo ""
    echo "Please install Redis:"
    echo "  Ubuntu/Debian: sudo apt-get install redis-server"
    echo "  macOS:         brew install redis"
    echo "  Windows:       Download from https://github.com/microsoftarchive/redis/releases"
    exit 1
fi

# Start Redis with appropriate configuration
echo "Starting Redis on localhost:6379..."
echo "Press Ctrl+C to stop Redis"
echo ""

redis-server --appendonly no --port 6379

