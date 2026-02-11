#!/bin/bash
# Lilith Zero - MCP Security Middleware Setup & Launcher
# Native Shell Script for macOS/Linux (and Git Bash on Windows)

set -e

echo -e "\n------------------------------------------------------------"
echo -e " \033[36mLILITH ZERO - MCP SECURITY MIDDLEWARE SETUP\033[0m "
echo -e "------------------------------------------------------------"

# 1. Environment Detection
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$SCRIPT_DIR/../../" && pwd )"

# Detect OS for binary and python paths
OS_TYPE="$(uname -s)"
if [[ "$OS_TYPE" == *"NT"* ]] || [[ "$OS_TYPE" == *"MINGW"* ]] || [[ "$OS_TYPE" == *"MSYS"* ]]; then
    IS_WINDOWS=true
    BINARY_NAME="lilith-zero.exe"
    PYTHON_EXEC="$ROOT_DIR/.venv/Scripts/python.exe"
    PYTHON_CMD="python"
else
    IS_WINDOWS=false
    BINARY_NAME="lilith-zero"
    PYTHON_EXEC="$ROOT_DIR/.venv/bin/python3"
    PYTHON_CMD="python3"
fi

BINARY_PATH="$ROOT_DIR/lilith-zero/target/release/$BINARY_NAME"
VENV_DIR="$ROOT_DIR/.venv"

# 2. Check Prerequisites
command -v cargo >/dev/null 2>&1 || { echo >&2 "[ERROR] cargo is required but not installed. Please install Rust."; exit 1; }
command -v $PYTHON_CMD >/dev/null 2>&1 || { echo >&2 "[ERROR] $PYTHON_CMD is required but not installed."; exit 1; }

HAS_UV=false
if command -v uv >/dev/null 2>&1; then
    HAS_UV=true
    echo "[OK] uv is installed."
fi

# 3. Build Middleware (Rust)
echo -e "\n[STEP 1/3] Building Lilith Zero Middleware (Rust)..."
cd "$ROOT_DIR/lilith-zero"
cargo build --release
echo -e "\033[32mMiddleware build successful.\033[0m"

# 4. Setup Python Environment
echo -e "\n[STEP 2/3] Preparing Python Sandbox Environment..."
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    if [ "$HAS_UV" = true ]; then
        uv venv "$VENV_DIR"
    else
        $PYTHON_CMD -m venv "$VENV_DIR"
    fi
fi

echo "Installing/Updating dependencies..."
cd "$ROOT_DIR"

# Set environment variables to force isolation
export VIRTUAL_ENV="$VENV_DIR"
export UV_PYTHON="$PYTHON_EXEC"

if [ "$HAS_UV" = true ]; then
    uv pip install --python "$PYTHON_EXEC" --no-system -r requirements.txt
else
    "$PYTHON_EXEC" -m pip install -r requirements.txt
fi

# 5. Run Demo
echo -e "\n[STEP 3/3] Launching Security Demo..."
echo -e "\033[90mStarting interactive session...\033[0m\n"

# Ensure we use the correct Python from venv to run the demo
"$PYTHON_EXEC" "$SCRIPT_DIR/secure_vibe_demo.py"
