# PowerShell wrapper for start_mcp.sh
# Usage: .\scripts\start_mcp.ps1

$scriptPath = Join-Path $PSScriptRoot "start_mcp.sh"
bash $scriptPath

