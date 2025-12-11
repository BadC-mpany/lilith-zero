# scripts/backend/run_mcp_wrapper.ps1
# Wrapper to run MCP Server with environment activation

$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Parent $scriptPath
$projectRoot = Split-Path -Parent (Split-Path -Parent $scriptDir)

# Import Utils
# Import Utils
$envUtils = Join-Path $projectRoot "scripts\utils\env_utils.ps1"
. $envUtils

Write-Host "=== MCP Server ===" -ForegroundColor Cyan
Write-Host "Initializing..." -ForegroundColor Gray

# Load .env
Load-EnvFile -Path (Join-Path $projectRoot "sentinel_core\interceptor\rust\.env")

$runMcpPy = Join-Path $scriptDir "run_mcp.py"

Invoke-WithEnvironment -ScriptBlock {
    Write-Host "Starting MCP Server..." -ForegroundColor Yellow
    # $runMcpPy is available from parent scope in dot-sourced/scriptblock context usually, 
    # but to be safe let's use $using:runMcpPy if it was Invoke-Command, but here it is local &. 
    # Local & inherits scope.
    python $runMcpPy
}

# Keep window open if it crashes immediately
if ($LASTEXITCODE -ne 0) {
    Write-Host "`nMCP Server exited with error code $LASTEXITCODE" -ForegroundColor Red
    Read-Host "Press Enter to exit..."
}
