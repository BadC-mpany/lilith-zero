# start_redis_docker.ps1
# Start Redis using Docker Compose

Write-Host "=== Starting Redis (Docker) ===" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

# Check if Docker is running
try {
    docker info | Out-Null
    Write-Host "  [OK] Docker is running" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Docker is not running" -ForegroundColor Red
    Write-Host "    Start Docker Desktop and try again" -ForegroundColor Yellow
    exit 1
}

# Start Redis
Write-Host "`n[1] Starting Redis container..." -ForegroundColor Yellow
Set-Location $projectRoot
docker-compose -f docker-compose.local.yml up -d redis

if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Redis container started" -ForegroundColor Green
    
    # Wait for health check
    Write-Host "`n[2] Waiting for Redis to be healthy..." -ForegroundColor Yellow
    $maxWait = 30
    $waited = 0
    while ($waited -lt $maxWait) {
        $health = docker inspect --format='{{.State.Health.Status}}' sentinel-redis-local 2>&1
        if ($health -eq "healthy") {
            Write-Host "  [OK] Redis is healthy" -ForegroundColor Green
            break
        }
        Start-Sleep -Seconds 2
        $waited += 2
        Write-Host "    Waiting... ($waited/$maxWait seconds)" -ForegroundColor Gray
    }
    
    if ($waited -ge $maxWait) {
        Write-Host "  [WARN] Redis health check timeout" -ForegroundColor Yellow
    }
    
    # Test connection
    Write-Host "`n[3] Testing Redis connection..." -ForegroundColor Yellow
    $result = docker exec sentinel-redis-local redis-cli ping 2>&1
    if ($result -eq "PONG") {
        Write-Host "  [OK] Redis is responding" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Redis ping failed: $result" -ForegroundColor Yellow
    }
    
    Write-Host "`n=== Redis Started ===" -ForegroundColor Green
    Write-Host "Redis URL: redis://localhost:6379/0" -ForegroundColor Cyan
} else {
    Write-Host "  [FAIL] Failed to start Redis container" -ForegroundColor Red
    exit 1
}

