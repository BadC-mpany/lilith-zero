#!/bin/bash
# Start Sentinel Interceptor Service
# Usage: ./start_interceptor.sh

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "Starting Sentinel Interceptor Service"
echo "=========================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "ERROR: Python not found!"
    echo "Please install Python 3.10 or higher"
    exit 1
fi

# Use python3 if available, otherwise python
PYTHON_CMD=$(command -v python3 || command -v python)

# Check if keys exist
PRIVATE_KEY_PATH="sentinel_core/secrets/interceptor_private.pem"
if [ ! -f "$PRIVATE_KEY_PATH" ]; then
    echo "ERROR: Private key not found at $PRIVATE_KEY_PATH"
    echo ""
    echo "Please generate keys first:"
    echo "  $PYTHON_CMD sentinel_core/keygen/src/key_gen.py"
    exit 1
fi

# Check if policies.yaml exists
POLICIES_PATH="sentinel_core/policies.yaml"
if [ ! -f "$POLICIES_PATH" ]; then
    echo "WARNING: policies.yaml not found at $POLICIES_PATH"
    echo "Interceptor may not work correctly without policies"
fi

# Check if Redis is running
if ! redis-cli ping &> /dev/null; then
    echo "WARNING: Redis does not appear to be running!"
    echo "Please start Redis first: ./start_redis.sh"
    echo ""
    echo "Continuing anyway..."
fi

# Set environment variables
export REDIS_HOST="${REDIS_HOST:-localhost}"
export REDIS_PORT="${REDIS_PORT:-6379}"
export REDIS_DB="${REDIS_DB:-0}"
export INTERCEPTOR_PRIVATE_KEY_PATH="${INTERCEPTOR_PRIVATE_KEY_PATH:-$SCRIPT_DIR/$PRIVATE_KEY_PATH}"
export POLICIES_YAML_PATH="${POLICIES_YAML_PATH:-$SCRIPT_DIR/$POLICIES_PATH}"

# Set PYTHONPATH
export PYTHONPATH="$SCRIPT_DIR/sentinel_core/interceptor/python/src:$SCRIPT_DIR/sentinel_core/mcp/src:$SCRIPT_DIR/sentinel_core/shared/python/src:$SCRIPT_DIR/sentinel_agent/src:$SCRIPT_DIR/sentinel_sdk/src"

# Check if dependencies are installed
echo "Checking dependencies..."
if ! $PYTHON_CMD -c "import fastapi, uvicorn, redis, jwt, cryptography" 2>/dev/null; then
    echo "Installing dependencies..."
    $PYTHON_CMD -m pip install -q -r sentinel_core/interceptor/python/requirements.txt
fi

echo ""
echo "Configuration:"
echo "  Redis:        $REDIS_HOST:$REDIS_PORT (DB $REDIS_DB)"
echo "  Private Key:  $INTERCEPTOR_PRIVATE_KEY_PATH"
echo "  Policies:     $POLICIES_YAML_PATH"
echo "  Port:         8000"
echo ""
echo "Starting Interceptor Service..."
echo "Press Ctrl+C to stop"
echo ""

# Change to the interceptor src directory and run
cd sentinel_core/interceptor/python/src
$PYTHON_CMD interceptor_service.py

