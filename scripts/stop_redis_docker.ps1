# stop_redis_docker.ps1
# Stop Redis Docker container

Write-Host "=== Stopping Redis (Docker) ===" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

Set-Location $projectRoot
docker-compose -f docker-compose.local.yml stop redis

if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Redis stopped" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Failed to stop Redis (may not be running)" -ForegroundColor Yellow
}

