# check_redis_mode.ps1
# Detect and report current Redis mode

Write-Host "=== Redis Mode Detection ===" -ForegroundColor Cyan

# Check REDIS_MODE environment variable
$redisMode = $env:REDIS_MODE
if ($redisMode) {
    Write-Host "`n[1] REDIS_MODE environment variable:" -ForegroundColor Yellow
    Write-Host "  Value: $redisMode" -ForegroundColor Gray
} else {
    Write-Host "`n[1] REDIS_MODE environment variable:" -ForegroundColor Yellow
    Write-Host "  Not set (defaults to 'docker')" -ForegroundColor Gray
    $redisMode = "docker"
}

# Check Docker container status
Write-Host "`n[2] Docker Redis container:" -ForegroundColor Yellow
try {
    $dockerContainer = docker ps --filter "name=sentinel-redis-local" --format "{{.Names}}" 2>&1
    if ($dockerContainer -eq "sentinel-redis-local") {
        $dockerStatus = docker inspect --format='{{.State.Status}}' sentinel-redis-local 2>&1
        Write-Host "  Status: Running ($dockerStatus)" -ForegroundColor Green
        $dockerAvailable = $true
    } else {
        Write-Host "  Status: Not running" -ForegroundColor Yellow
        $dockerAvailable = $false
    }
} catch {
    Write-Host "  Status: Docker not available or container not found" -ForegroundColor Yellow
    $dockerAvailable = $false
}

# Check WSL Redis status
Write-Host "`n[3] WSL Redis:" -ForegroundColor Yellow
try {
    $wslTest = wsl redis-cli ping 2>&1
    if ($wslTest -eq "PONG") {
        Write-Host "  Status: Running" -ForegroundColor Green
        $wslAvailable = $true
    } else {
        Write-Host "  Status: Not responding" -ForegroundColor Yellow
        $wslAvailable = $false
    }
} catch {
    Write-Host "  Status: WSL not available or Redis not running" -ForegroundColor Yellow
    $wslAvailable = $false
}

# Report recommended mode
Write-Host "`n=== Recommendation ===" -ForegroundColor Cyan
if ($redisMode -eq "auto") {
    if ($dockerAvailable) {
        Write-Host "Auto mode detected Docker Redis - using Docker mode" -ForegroundColor Green
    } elseif ($wslAvailable) {
        Write-Host "Auto mode detected WSL Redis - using WSL mode" -ForegroundColor Yellow
    } else {
        Write-Host "Auto mode: Neither Docker nor WSL Redis available" -ForegroundColor Red
        Write-Host "  Start one of:" -ForegroundColor Yellow
        Write-Host "    - Docker: .\scripts\start_redis_docker.ps1" -ForegroundColor Gray
        Write-Host "    - WSL: wsl redis-server --daemonize yes" -ForegroundColor Gray
    }
} else {
    Write-Host "Using explicit mode: $redisMode" -ForegroundColor Green
    if ($redisMode -eq "docker" -and -not $dockerAvailable) {
        Write-Host "  [WARN] Docker mode selected but Docker Redis not running" -ForegroundColor Yellow
        Write-Host "    Start with: .\scripts\start_redis_docker.ps1" -ForegroundColor Gray
    } elseif ($redisMode -eq "wsl" -and -not $wslAvailable) {
        Write-Host "  [WARN] WSL mode selected but WSL Redis not running" -ForegroundColor Yellow
        Write-Host "    Start with: wsl redis-server --daemonize yes" -ForegroundColor Gray
    }
}

