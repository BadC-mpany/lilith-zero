# Quick Start: Interceptor Only
# This script starts just the Rust interceptor (no MCP, no agent)

Write-Host "=== Starting Interceptor Only ===" -ForegroundColor Cyan

# 1. Ensure Redis is running
Write-Host "`n[1] Checking Redis..." -ForegroundColor Yellow
$redisCheck = docker ps --filter "name=sentinel-redis-local" --format "{{.Names}}"
if ($redisCheck -ne "sentinel-redis-local") {
    Write-Host "  Redis not running, starting..." -ForegroundColor Yellow
    & "$PSScriptRoot\backend\start_redis_docker.ps1"
} else {
    Write-Host "  [OK] Redis is running" -ForegroundColor Green
}

# 2. Start Interceptor
Write-Host "`n[2] Starting Interceptor..." -ForegroundColor Yellow
& "$PSScriptRoot\backend\run_interceptor_wrapper.ps1"
