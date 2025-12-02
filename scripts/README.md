# Sentinel Scripts

This directory contains all executable scripts for running Sentinel services.

## Scripts

### `start_redis.sh`

Starts the Redis server required by Sentinel services.

- Checks if Redis is already running
- Provides installation instructions if Redis is not found
- Works on Windows (WSL/Git Bash), macOS, and Linux

**Usage:**

**Windows (PowerShell):**
```powershell
bash scripts/start_redis.sh
# OR use PowerShell wrapper:
.\scripts\start_redis.ps1
```

**Windows (Git Bash) / macOS / Linux:**
```bash
./scripts/start_redis.sh
```

### `start_interceptor.sh`

Starts the Sentinel Interceptor service (Zone B - Policy Enforcement Point).

- Automatically detects Python virtual environment
- Sets up PYTHONPATH and environment variables
- Handles cross-platform path conversion (Windows/Unix)
- Runs on `http://localhost:8000`

**Usage:**

**Windows (PowerShell):**
```powershell
# Make sure virtual environment is activated first
.\sentinel_env\Scripts\Activate.ps1
bash scripts/start_interceptor.sh
# OR use PowerShell wrapper:
.\scripts\start_interceptor.ps1
```

**Windows (Git Bash) / macOS / Linux:**
```bash
# Make sure virtual environment is activated first
source sentinel_env/bin/activate  # or: . sentinel_env/bin/activate
./scripts/start_interceptor.sh
```

**Prerequisites:**

- Virtual environment activated (or `sentinel_env` directory exists)
- Redis running
- Cryptographic keys generated (`sentinel_core/secrets/interceptor_private.pem`)

### `start_mcp.sh`

Starts the Sentinel MCP Server (Zone C - Secure Execution Environment).

- Automatically detects Python virtual environment
- Sets up PYTHONPATH and environment variables
- Handles cross-platform path conversion (Windows/Unix)
- Runs on `http://localhost:9000`

**Usage:**

**Windows (PowerShell):**
```powershell
# Make sure virtual environment is activated first
.\sentinel_env\Scripts\Activate.ps1
bash scripts/start_mcp.sh
# OR use PowerShell wrapper:
.\scripts\start_mcp.ps1
```

**Windows (Git Bash) / macOS / Linux:**
```bash
# Make sure virtual environment is activated first
source sentinel_env/bin/activate  # or: . sentinel_env/bin/activate
./scripts/start_mcp.sh
```

**Prerequisites:**

- Virtual environment activated (or `sentinel_env` directory exists)
- Redis running
- Cryptographic keys generated (`sentinel_core/secrets/mcp_public.pem`)

## Wrapper Scripts

### `run_interceptor.py`

Python wrapper script for `interceptor_service.py`.

- Sets up `sys.path` for module imports
- Configures environment variables
- Handles path normalization for cross-platform compatibility
- Called automatically by `start_interceptor.sh`

### `run_mcp.py`

Python wrapper script for `mcp_server.py`.

- Sets up `sys.path` for module imports
- Configures environment variables
- Handles path normalization for cross-platform compatibility
- Called automatically by `start_mcp.sh`

## Cross-Platform Support

All scripts are designed to work on:

- **Windows**: Git Bash, WSL, PowerShell
- **macOS**: Terminal, zsh, bash
- **Linux**: bash, sh

The scripts automatically detect the operating system and Python environment, converting paths as needed for Windows Python executables.

## Environment Variables

The scripts set the following environment variables (can be overridden):

- `REDIS_HOST`: Redis server hostname (default: `localhost`)
- `REDIS_PORT`: Redis server port (default: `6379`)
- `REDIS_DB`: Redis database number (default: `0` for Interceptor, `1` for MCP)
- `SENTINEL_SCRIPT_DIR`: Project root directory
- `INTERCEPTOR_PRIVATE_KEY_PATH`: Path to interceptor private key
- `MCP_PUBLIC_KEY_PATH`: Path to MCP public key
- `POLICIES_YAML_PATH`: Path to policies configuration file
- `TOOL_REGISTRY_PATH`: Path to tool registry YAML file
