# PowerShell wrapper for start_redis.sh
# Usage: .\scripts\start_redis.ps1

$scriptPath = Join-Path $PSScriptRoot "start_redis.sh"
bash $scriptPath

