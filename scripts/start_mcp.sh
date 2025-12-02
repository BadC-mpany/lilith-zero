#!/bin/bash
# Start Sentinel MCP Server
# Usage: ./start_mcp.sh

set -e

# Get the directory where this script is located (scripts/)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Get project root (one level up from scripts/)
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
cd "$PROJECT_ROOT"

echo "=========================================="
echo "Starting Sentinel MCP Server"
echo "=========================================="

# Detect Python - prefer activated virtual environment, then common venv names, then system Python
PYTHON_CMD=""
VENV_NAME=""

# Check if virtual environment is already activated
if [ -n "$VIRTUAL_ENV" ]; then
    if [ -f "$VIRTUAL_ENV/Scripts/python.exe" ]; then
        PYTHON_CMD="$VIRTUAL_ENV/Scripts/python.exe"
        VENV_NAME=$(basename "$VIRTUAL_ENV")
    elif [ -f "$VIRTUAL_ENV/bin/python" ]; then
        PYTHON_CMD="$VIRTUAL_ENV/bin/python"
        VENV_NAME=$(basename "$VIRTUAL_ENV")
    fi
fi

# If no activated venv, check for common venv directory names (in project root)
if [ -z "$PYTHON_CMD" ]; then
    for venv_dir in venv .venv env sentinel_env; do
        if [ -f "$PROJECT_ROOT/$venv_dir/Scripts/python.exe" ]; then
            PYTHON_CMD="$PROJECT_ROOT/$venv_dir/Scripts/python.exe"
            VENV_NAME="$venv_dir"
            break
        elif [ -f "$PROJECT_ROOT/$venv_dir/bin/python" ]; then
            PYTHON_CMD="$PROJECT_ROOT/$venv_dir/bin/python"
            VENV_NAME="$venv_dir"
            break
        fi
    done
fi

# Detect OS for path handling (do this early)
# Check multiple indicators for Windows
IS_WINDOWS=false
PATH_SEP=":"
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ -n "$WINDIR" ]] || [[ "$OSTYPE" == *"msys"* ]] || [[ -d "/c/Windows" ]] || [[ -d "/mnt/c/Windows" ]]; then
    IS_WINDOWS=true
    PATH_SEP=";"
fi

# Display which Python/venv we're using
if [ -n "$VENV_NAME" ]; then
    echo "Using virtual environment: $VENV_NAME"
elif [ -n "$PYTHON_CMD" ]; then
    echo "Using Python: $PYTHON_CMD"
fi

# If still no Python found, try system Python
if [ -z "$PYTHON_CMD" ]; then
    # Check for Windows py launcher
    if command -v py &> /dev/null 2>&1; then
        PYTHON_CMD="py"
        echo "Using Windows Python launcher"
    # Check for Windows Python in common locations
    elif [ -f "/c/Windows/System32/python.exe" ]; then
        PYTHON_CMD="/c/Windows/System32/python.exe"
    elif command -v python &> /dev/null 2>&1; then
        PYTHON_PATH=$(command -v python)
        # Avoid WSL python if we're in Git Bash on Windows
        if [[ "$PYTHON_PATH" != *"/usr/bin/"* ]] && [[ "$PYTHON_PATH" != *"/mnt/"* ]]; then
            PYTHON_CMD="$PYTHON_PATH"
        fi
    fi
    
    # If still no Python found, try python3 but warn (avoid WSL)
    if [ -z "$PYTHON_CMD" ]; then
        if command -v python3 &> /dev/null 2>&1; then
            PYTHON_PATH=$(command -v python3)
            # Only use if not WSL python
            if [[ "$PYTHON_PATH" != *"/usr/bin/"* ]] && [[ "$PYTHON_PATH" != *"/mnt/"* ]]; then
                PYTHON_CMD="$PYTHON_PATH"
                echo "WARNING: Using system python3. Consider using a virtual environment."
            fi
        fi
    fi
    
    # Final fallback - use python3 (works on all platforms)
    if [ -z "$PYTHON_CMD" ]; then
        if command -v python3 &> /dev/null 2>&1; then
            PYTHON_CMD=$(command -v python3)
            if [[ "$PYTHON_CMD" == *"/usr/bin/"* ]] || [[ "$PYTHON_CMD" == *"/mnt/"* ]]; then
                echo "WARNING: Using WSL/system Python. Consider using a virtual environment."
            else
                echo "WARNING: Using system python3. Consider using a virtual environment."
            fi
            if [[ "$IS_WINDOWS" == "true" ]]; then
                echo "  Activate venv: .\\venv\\Scripts\\Activate.ps1  (or your venv name)"
            else
                echo "  Activate venv: source venv/bin/activate  (or your venv name)"
            fi
        fi
    fi
fi

# Check if Python is installed
if [ -z "$PYTHON_CMD" ] || [ ! -f "$PYTHON_CMD" ]; then
    echo "ERROR: Python not found!"
    echo "Please install Python 3.10 or higher"
    exit 1
fi

# Check if keys exist (in project root)
PUBLIC_KEY_PATH="sentinel_core/secrets/mcp_public.pem"
if [ ! -f "$PROJECT_ROOT/$PUBLIC_KEY_PATH" ]; then
    echo "ERROR: Public key not found at $PROJECT_ROOT/$PUBLIC_KEY_PATH"
    echo ""
    echo "Please generate keys first:"
    echo "  $PYTHON_CMD $PROJECT_ROOT/sentinel_core/keygen/src/key_gen.py"
    exit 1
fi

# Check if Redis is running (non-blocking, skip if redis-cli not available)
if command -v redis-cli &> /dev/null; then
    if ! redis-cli ping &> /dev/null 2>&1; then
        echo "WARNING: Redis does not appear to be running!"
        echo "Please start Redis first: ./scripts/start_redis.sh"
        echo ""
        echo "Continuing anyway..."
    fi
else
    echo "NOTE: redis-cli not found, skipping Redis check"
    echo "Make sure Redis is running on $REDIS_HOST:$REDIS_PORT"
fi

# Set environment variables
export REDIS_HOST="${REDIS_HOST:-localhost}"
export REDIS_PORT="${REDIS_PORT:-6379}"
export REDIS_DB="${REDIS_DB:-1}"

# Convert paths based on OS and Python type (using PROJECT_ROOT)
if [[ "$IS_WINDOWS" == "true" ]] && ([[ "$PYTHON_CMD" == *".exe" ]] || [[ "$PYTHON_CMD" == "py" ]]); then
    # Windows Python - convert WSL/Git Bash paths to Windows format
    if [[ "$PROJECT_ROOT" == /mnt/* ]]; then
        DRIVE_LETTER=$(echo "$PROJECT_ROOT" | sed 's|/mnt/\([a-z]\).*|\1|' | tr '[:lower:]' '[:upper:]')
        WIN_PROJECT_ROOT=$(echo "$PROJECT_ROOT" | sed "s|/mnt/[a-z]|${DRIVE_LETTER}:|")
    elif [[ "$PROJECT_ROOT" == /c/* ]]; then
        WIN_PROJECT_ROOT=$(echo "$PROJECT_ROOT" | sed 's|/c/|C:/|')
    else
        WIN_PROJECT_ROOT="$PROJECT_ROOT"
    fi
    export MCP_PUBLIC_KEY_PATH="${MCP_PUBLIC_KEY_PATH:-${WIN_PROJECT_ROOT}/${PUBLIC_KEY_PATH}}"
else
    # Unix/Mac/Linux - use standard paths
    export MCP_PUBLIC_KEY_PATH="${MCP_PUBLIC_KEY_PATH:-$PROJECT_ROOT/$PUBLIC_KEY_PATH}"
fi

# Set PYTHONPATH with appropriate separator (using PROJECT_ROOT)
if [[ "$IS_WINDOWS" == "true" ]] && ([[ "$PYTHON_CMD" == *".exe" ]] || [[ "$PYTHON_CMD" == "py" ]]); then
    # Windows Python - convert paths and use semicolon separator
    if [[ "$PROJECT_ROOT" == /mnt/* ]]; then
        # Convert /mnt/c/... to C:/... (uppercase drive letter, forward slashes)
        DRIVE_LETTER=$(echo "$PROJECT_ROOT" | sed 's|/mnt/\([a-z]\).*|\1|' | tr '[:lower:]' '[:upper:]')
        WIN_PROJECT_ROOT=$(echo "$PROJECT_ROOT" | sed "s|/mnt/[a-z]|${DRIVE_LETTER}:|")
    elif [[ "$PROJECT_ROOT" == /c/* ]]; then
        WIN_PROJECT_ROOT=$(echo "$PROJECT_ROOT" | sed 's|/c/|C:/|')
    else
        WIN_PROJECT_ROOT="$PROJECT_ROOT"
    fi
    # Use forward slashes and semicolon separator for Windows PYTHONPATH
    PYTHONPATH="${WIN_PROJECT_ROOT}/sentinel_core/interceptor/python/src${PATH_SEP}${WIN_PROJECT_ROOT}/sentinel_core/mcp/src${PATH_SEP}${WIN_PROJECT_ROOT}/sentinel_core/shared/python/src${PATH_SEP}${WIN_PROJECT_ROOT}/sentinel_agent/src${PATH_SEP}${WIN_PROJECT_ROOT}/sentinel_sdk/src"
    export PYTHONPATH
else
    # Unix/Mac/Linux - use colon separator
    PYTHONPATH="$PROJECT_ROOT/sentinel_core/interceptor/python/src:$PROJECT_ROOT/sentinel_core/mcp/src:$PROJECT_ROOT/sentinel_core/shared/python/src:$PROJECT_ROOT/sentinel_agent/src:$PROJECT_ROOT/sentinel_sdk/src"
    export PYTHONPATH
fi

# Display PYTHONPATH for debugging (first path only)
if [[ "${DEBUG:-0}" == "1" ]]; then
    echo "DEBUG: PYTHONPATH=$PYTHONPATH"
fi

# Check if dependencies are installed
echo "Checking dependencies..."
if ! $PYTHON_CMD -c "import fastapi, uvicorn, redis, jwt, cryptography" 2>/dev/null; then
    echo "Installing dependencies..."
    if ! $PYTHON_CMD -m pip --version &> /dev/null 2>&1; then
        echo "ERROR: pip not available for $PYTHON_CMD"
        echo ""
        echo "If you're using a virtual environment, activate it first:"
        if [[ "$IS_WINDOWS" == "true" ]]; then
            echo "  .\\venv\\Scripts\\Activate.ps1  (or your venv name)"
        else
            echo "  source venv/bin/activate  (or your venv name)"
        fi
        echo ""
        echo "Or install dependencies manually:"
        echo "  pip install -r $PROJECT_ROOT/sentinel_core/mcp/requirements.txt"
        exit 1
    fi
    $PYTHON_CMD -m pip install -q -r "$PROJECT_ROOT/sentinel_core/mcp/requirements.txt"
fi

echo ""
echo "Configuration:"
echo "  Redis:       $REDIS_HOST:$REDIS_PORT (DB $REDIS_DB)"
echo "  Public Key:  $MCP_PUBLIC_KEY_PATH"
echo "  Port:        9000"
echo ""
echo "Starting MCP Server..."
echo "Press Ctrl+C to stop"
echo ""

# Debug: Show PYTHONPATH before running
if [[ "${DEBUG:-0}" == "1" ]]; then
    echo "DEBUG: PYTHONPATH=$PYTHONPATH"
    echo "DEBUG: Python command: $PYTHON_CMD"
    echo "DEBUG: Script dir: $SCRIPT_DIR"
    echo "DEBUG: Is Windows: $IS_WINDOWS"
fi

# Convert SCRIPT_DIR to Windows format if needed for wrapper script
if [[ "$IS_WINDOWS" == "true" ]] && ([[ "$PYTHON_CMD" == *".exe" ]] || [[ "$PYTHON_CMD" == "py" ]]); then
    # Convert paths for Windows Python - handle /mnt/c/... format from Git Bash
    echo "=== PATH CONVERSION DEBUG ==="
    echo "IS_WINDOWS: $IS_WINDOWS"
    echo "PYTHON_CMD: $PYTHON_CMD"
    echo "SCRIPT_DIR (scripts/): $SCRIPT_DIR"
    echo "PROJECT_ROOT: $PROJECT_ROOT"
    
    if [[ "$PROJECT_ROOT" == /mnt/* ]]; then
        echo "Path starts with /mnt/, converting..."
        # Use Python to convert /mnt/c/... to C:/... (WITHOUT suppressing errors)
        WIN_SCRIPT_DIR=$($PYTHON_CMD -c "
import re
import sys
path = '$PROJECT_ROOT'
match = re.match(r'/mnt/([a-z])(.*)', path)
if match:
    drive = match.group(1).upper()
    rest = match.group(2)
    print(f'{drive}:{rest}', end='')
else:
    print(path, end='')
" 2>&1)
        # Strip any trailing whitespace/newlines
        WIN_SCRIPT_DIR=$(echo "$WIN_SCRIPT_DIR" | tr -d '\r\n' | sed 's/[[:space:]]*$//')
        # Fallback if Python conversion fails
        if [[ -z "$WIN_SCRIPT_DIR" ]] || [[ "$WIN_SCRIPT_DIR" == /mnt/* ]]; then
            DRIVE_LOWER=$(echo "$PROJECT_ROOT" | sed -n 's|/mnt/\([a-z]\).*|\1|p')
            DRIVE_UPPER=$(echo "$DRIVE_LOWER" | tr '[:lower:]' '[:upper:]')
            REST_PATH=$(echo "$PROJECT_ROOT" | sed -n "s|/mnt/$DRIVE_LOWER||p")
            WIN_SCRIPT_DIR="${DRIVE_UPPER}:${REST_PATH}"
        fi
    elif [[ "$PROJECT_ROOT" == /c/* ]] || [[ "$PROJECT_ROOT" == /C/* ]]; then
        REST_PATH=$(echo "$PROJECT_ROOT" | sed 's|^/c/||' | sed 's|^/C/||')
        WIN_SCRIPT_DIR="C:/${REST_PATH}"
    else
        WIN_SCRIPT_DIR="$PROJECT_ROOT"
    fi
    
    echo "FINAL WIN_SCRIPT_DIR (PROJECT_ROOT): $WIN_SCRIPT_DIR"
    
    # Convert SCRIPT_DIR to Windows format for wrapper script path
    if [[ "$SCRIPT_DIR" == /mnt/* ]]; then
        DRIVE_LOWER=$(echo "$SCRIPT_DIR" | sed 's|^/mnt/\([a-z]\).*|\1|')
        DRIVE_UPPER=$(echo "$DRIVE_LOWER" | tr '[:lower:]' '[:upper:]')
        REST_PATH="${SCRIPT_DIR#/mnt/$DRIVE_LOWER}"
        WIN_SCRIPTS_DIR="${DRIVE_UPPER}:${REST_PATH}"
    elif [[ "$SCRIPT_DIR" == /c/* ]] || [[ "$SCRIPT_DIR" == /C/* ]]; then
        REST_PATH=$(echo "$SCRIPT_DIR" | sed 's|^/c/||' | sed 's|^/C/||')
        WIN_SCRIPTS_DIR="C:/${REST_PATH}"
    else
        WIN_SCRIPTS_DIR="$SCRIPT_DIR"
    fi
    
    echo "WIN_SCRIPTS_DIR (scripts/): $WIN_SCRIPTS_DIR"
    echo "=== END PATH CONVERSION DEBUG ==="
    
    # Export environment variables for Python (use Windows paths, PROJECT_ROOT)
    export SENTINEL_SCRIPT_DIR="$WIN_SCRIPT_DIR"
    export MCP_PUBLIC_KEY_PATH="${MCP_PUBLIC_KEY_PATH:-${WIN_SCRIPT_DIR}/sentinel_core/secrets/mcp_public.pem}"
    
    echo "Environment variables being set:"
    echo "  SENTINEL_SCRIPT_DIR=$SENTINEL_SCRIPT_DIR"
    echo "  MCP_PUBLIC_KEY_PATH=$MCP_PUBLIC_KEY_PATH"
    
    # Try using wrapper script first (more reliable for Windows)
    # Check file exists using bash path, but use Windows path for Python
    if [ -f "$SCRIPT_DIR/run_mcp.py" ]; then
        echo "Wrapper script found! Executing: $PYTHON_CMD \"$WIN_SCRIPTS_DIR/run_mcp.py\""
        # Use forward slashes for Windows Python (it accepts them)
        # Pass ALL environment variables explicitly - Windows Python doesn't inherit bash exports
        env MCP_PUBLIC_KEY_PATH="$MCP_PUBLIC_KEY_PATH" \
            SENTINEL_SCRIPT_DIR="$WIN_SCRIPT_DIR" \
            REDIS_HOST="$REDIS_HOST" \
            REDIS_PORT="$REDIS_PORT" \
            REDIS_DB="$REDIS_DB" \
            $PYTHON_CMD "$WIN_SCRIPTS_DIR/run_mcp.py"
    else
        # Fallback: Use Python to set paths and then run the script directly
        cd "$PROJECT_ROOT/sentinel_core/mcp/src"
        
        $PYTHON_CMD -c "
import sys, os
paths = [
    '$WIN_SCRIPT_DIR/sentinel_core/interceptor/python/src',
    '$WIN_SCRIPT_DIR/sentinel_core/mcp/src',
    '$WIN_SCRIPT_DIR/sentinel_core/shared/python/src',
    '$WIN_SCRIPT_DIR/sentinel_agent/src',
    '$WIN_SCRIPT_DIR/sentinel_sdk/src'
]
for p in paths:
    if p and p not in sys.path:
        sys.path.insert(0, p)
os.chdir('$WIN_SCRIPT_DIR/sentinel_core/mcp/src')
with open('mcp_server.py', 'rb') as f:
    code = compile(f.read(), 'mcp_server.py', 'exec')
    exec(code)
"
    fi
else
    # Unix/Mac/Linux - PYTHONPATH should work
    export SENTINEL_SCRIPT_DIR="$SCRIPT_DIR"
    export MCP_PUBLIC_KEY_PATH="${MCP_PUBLIC_KEY_PATH:-$SCRIPT_DIR/$PUBLIC_KEY_PATH}"
    
    # Try using wrapper script first
    if [ -f "$SCRIPT_DIR/run_mcp.py" ]; then
        env MCP_PUBLIC_KEY_PATH="$MCP_PUBLIC_KEY_PATH" \
            SENTINEL_SCRIPT_DIR="$SENTINEL_SCRIPT_DIR" \
            REDIS_HOST="$REDIS_HOST" \
            REDIS_PORT="$REDIS_PORT" \
            REDIS_DB="$REDIS_DB" \
            $PYTHON_CMD "$SCRIPT_DIR/run_mcp.py"
    else
        # Fallback: Change to the MCP src directory and run directly
        cd sentinel_core/mcp/src
        export PYTHONPATH
        $PYTHON_CMD mcp_server.py
    fi
fi

