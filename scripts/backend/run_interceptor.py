#!/usr/bin/env python3
"""Wrapper script to set up PYTHONPATH and run interceptor_service.py"""
import sys
import os

# Get script directory from environment or calculate from script location
script_dir = os.environ.get('SENTINEL_SCRIPT_DIR')
if not script_dir:
    # Calculate project root from this script's location (this script is in scripts/backend/)
    # Go up TWO levels to get project root (scripts/backend -> scripts -> root)
    script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    # Also set it in environment for other modules
    os.environ['SENTINEL_SCRIPT_DIR'] = script_dir

# Normalize the path (convert forward slashes to backslashes on Windows if needed)
script_dir = os.path.normpath(script_dir)
os.environ['SENTINEL_SCRIPT_DIR'] = script_dir  # Update with normalized path

# Set environment variables in Python if not already set (for other modules)
if 'SENTINEL_SCRIPT_DIR' not in os.environ:
    os.environ['SENTINEL_SCRIPT_DIR'] = script_dir
else:
    script_dir = os.environ['SENTINEL_SCRIPT_DIR']  # Use env var if set

# Set default paths if not in environment
if 'POLICIES_YAML_PATH' not in os.environ:
    os.environ['POLICIES_YAML_PATH'] = os.path.join(script_dir, "sentinel_core", "policies.yaml")

if 'TOOL_REGISTRY_PATH' not in os.environ:
    os.environ['TOOL_REGISTRY_PATH'] = os.path.join(script_dir, "rule_maker", "data", "tool_registry.yaml")

if 'INTERCEPTOR_PRIVATE_KEY_PATH' not in os.environ:
    os.environ['INTERCEPTOR_PRIVATE_KEY_PATH'] = os.path.join(script_dir, "sentinel_core", "secrets", "interceptor_private.pem")

# Debug output
print(f"Script directory: {script_dir}")
print(f"SENTINEL_SCRIPT_DIR env: {os.environ.get('SENTINEL_SCRIPT_DIR', 'NOT SET')}")
print(f"POLICIES_YAML_PATH env: {os.environ.get('POLICIES_YAML_PATH', 'NOT SET')}")
print(f"TOOL_REGISTRY_PATH env: {os.environ.get('TOOL_REGISTRY_PATH', 'NOT SET')}")
print(f"INTERCEPTOR_PRIVATE_KEY_PATH env: {os.environ.get('INTERCEPTOR_PRIVATE_KEY_PATH', 'NOT SET')}")

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

# Change to interceptor src directory using os.path.join
interceptor_src = os.path.join(script_dir, "sentinel_core", "interceptor", "python", "src")
if not os.path.exists(interceptor_src):
    print(f"ERROR: Interceptor source directory not found: {interceptor_src}")
    sys.exit(1)
os.chdir(interceptor_src)

# Import and run
if __name__ == "__main__":
    # Import the module (this will execute the module-level code)
    import interceptor_service
    # The module should have uvicorn.run in its __main__ block, but if not, run it here
    import uvicorn
    uvicorn.run(interceptor_service.app, host="0.0.0.0", port=8000)

