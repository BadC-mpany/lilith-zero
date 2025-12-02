#!/usr/bin/env python3
"""Wrapper script to set up PYTHONPATH and run mcp_server.py"""
import sys
import os

# Get script directory from environment or calculate from script location
script_dir = os.environ.get('SENTINEL_SCRIPT_DIR')
if not script_dir:
    # Calculate from this script's location (this script is in project root)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Also set it in environment for other modules
    os.environ['SENTINEL_SCRIPT_DIR'] = script_dir

# Normalize the path (convert forward slashes to backslashes on Windows if needed)
script_dir = os.path.normpath(script_dir)
os.environ['SENTINEL_SCRIPT_DIR'] = script_dir  # Update with normalized path

# Set default paths if not in environment
if 'MCP_PUBLIC_KEY_PATH' not in os.environ:
    os.environ['MCP_PUBLIC_KEY_PATH'] = os.path.join(script_dir, "sentinel_core", "secrets", "mcp_public.pem")

# Set default Redis environment variables if not provided
if 'REDIS_HOST' not in os.environ:
    os.environ['REDIS_HOST'] = 'localhost'
if 'REDIS_PORT' not in os.environ:
    os.environ['REDIS_PORT'] = '6379'
if 'REDIS_DB' not in os.environ:
    os.environ['REDIS_DB'] = '1'

# Set default tool registry path if not provided
if 'TOOL_REGISTRY_PATH' not in os.environ:
    os.environ['TOOL_REGISTRY_PATH'] = os.path.join(script_dir, "rule_maker", "data", "tool_registry.yaml")

# Debug output
print(f"Script directory: {script_dir}")
print(f"SENTINEL_SCRIPT_DIR env: {os.environ.get('SENTINEL_SCRIPT_DIR', 'NOT SET')}")
print(f"MCP_PUBLIC_KEY_PATH env: {os.environ.get('MCP_PUBLIC_KEY_PATH', 'NOT SET')}")
print(f"REDIS_HOST env: {os.environ.get('REDIS_HOST', 'NOT SET')}")
print(f"REDIS_PORT env: {os.environ.get('REDIS_PORT', 'NOT SET')}")
print(f"REDIS_DB env: {os.environ.get('REDIS_DB', 'NOT SET')}")
print(f"TOOL_REGISTRY_PATH env: {os.environ.get('TOOL_REGISTRY_PATH', 'NOT SET')}")

# Add paths to sys.path using os.path.join for cross-platform compatibility
paths = [
    os.path.join(script_dir, "sentinel_core", "interceptor", "python", "src"),
    os.path.join(script_dir, "sentinel_core", "mcp", "src"),
    os.path.join(script_dir, "sentinel_core", "shared", "python", "src"),
    os.path.join(script_dir, "sentinel_agent", "src"),
    os.path.join(script_dir, "sentinel_sdk", "src"),
]

for p in paths:
    p_abs = os.path.abspath(p)
    if os.path.exists(p_abs) and p_abs not in sys.path:
        sys.path.insert(0, p_abs)

# Change to MCP src directory using os.path.join
mcp_src = os.path.join(script_dir, "sentinel_core", "mcp", "src")
if not os.path.exists(mcp_src):
    print(f"ERROR: MCP source directory not found: {mcp_src}")
    sys.exit(1)
os.chdir(mcp_src)

# Import and run
if __name__ == "__main__":
    # Import the module (this will execute the module-level code)
    import mcp_server
    # The module should have uvicorn.run in its __main__ block, but if not, run it here
    import uvicorn
    uvicorn.run(mcp_server.app, host="0.0.0.0", port=9000)

