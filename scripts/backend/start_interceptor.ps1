# PowerShell wrapper for start_interceptor.sh
# Usage: .\scripts\start_interceptor.ps1

$scriptPath = Join-Path $PSScriptRoot "start_interceptor.sh"
bash $scriptPath

