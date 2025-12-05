# verify_services.ps1
Write-Host "=== Sentinel Integration Verification ===" -ForegroundColor Cyan

$allGood = $true

# Check PostgreSQL
Write-Host "`n[1] Checking PostgreSQL..." -ForegroundColor Yellow
try {
    $pgService = Get-Service | Where-Object { $_.Name -like "postgresql*" } | Select-Object -First 1
    if ($pgService -and $pgService.Status -eq "Running") {
        Write-Host "  [OK] PostgreSQL service is running" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] PostgreSQL service is stopped" -ForegroundColor Red
        if ($pgService) {
            Write-Host "    Service name: $($pgService.Name)" -ForegroundColor Gray
            Write-Host "    Start with: Start-Service $($pgService.Name)" -ForegroundColor Yellow
        }
        $allGood = $false
    }
} catch {
    Write-Host "  [FAIL] PostgreSQL service not found" -ForegroundColor Red
    $allGood = $false
}

# Check Redis (Docker or WSL based on REDIS_MODE)
Write-Host "`n[2] Checking Redis..." -ForegroundColor Yellow
$redisMode = $env:REDIS_MODE
if (-not $redisMode) {
    $redisMode = "docker"  # Default to Docker
}

if ($redisMode -eq "docker" -or $redisMode -eq "auto") {
    # Check Docker Redis
    try {
        $dockerContainer = docker ps --filter "name=sentinel-redis-local" --format "{{.Names}}" 2>&1
        if ($dockerContainer -eq "sentinel-redis-local") {
            $pingResult = docker exec sentinel-redis-local redis-cli ping 2>&1
            if ($pingResult -eq "PONG") {
                Write-Host "  [OK] Redis is running in Docker" -ForegroundColor Green
            } else {
                Write-Host "  [FAIL] Docker Redis not responding" -ForegroundColor Red
                Write-Host "    Response: $pingResult" -ForegroundColor Gray
                $allGood = $false
            }
        } else {
            if ($redisMode -eq "auto") {
                Write-Host "  [WARN] Docker Redis not running, checking WSL..." -ForegroundColor Yellow
                $redisMode = "wsl"  # Fallback to WSL check
            } else {
                Write-Host "  [FAIL] Docker Redis container not running" -ForegroundColor Red
                Write-Host "    Start with: .\scripts\start_redis_docker.ps1" -ForegroundColor Yellow
                $allGood = $false
            }
        }
    } catch {
        if ($redisMode -eq "auto") {
            Write-Host "  [WARN] Docker check failed, checking WSL..." -ForegroundColor Yellow
            $redisMode = "wsl"  # Fallback to WSL check
        } else {
            Write-Host "  [FAIL] Docker Redis check failed: $_" -ForegroundColor Red
            $allGood = $false
        }
    }
}

if ($redisMode -eq "wsl") {
    # Check WSL Redis
    try {
        $wslTest = wsl redis-cli ping 2>&1
        if ($wslTest -eq "PONG") {
            Write-Host "  [OK] Redis is running in WSL" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Redis not responding in WSL" -ForegroundColor Red
            Write-Host "    Response: $wslTest" -ForegroundColor Gray
            Write-Host "    Start with: wsl redis-server --daemonize yes" -ForegroundColor Yellow
            $allGood = $false
        }
    } catch {
        Write-Host "  [FAIL] WSL Redis check failed: $_" -ForegroundColor Red
        $allGood = $false
    }
}

# Check Rust Interceptor
Write-Host "`n[3] Checking Rust Interceptor..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 5 -ErrorAction Stop
    if ($response.StatusCode -eq 200) {
        Write-Host "  [OK] Rust Interceptor is running" -ForegroundColor Green
        Write-Host "    Response: $($response.Content)" -ForegroundColor Gray
    } else {
        Write-Host "  [FAIL] Rust Interceptor returned status $($response.StatusCode)" -ForegroundColor Red
        $allGood = $false
    }
} catch {
    Write-Host "  [FAIL] Rust Interceptor not responding on port 8000" -ForegroundColor Red
    Write-Host "    Error: $_" -ForegroundColor Gray
    Write-Host "    Start with: cd sentinel_core\interceptor\rust; cargo run --bin sentinel-interceptor" -ForegroundColor Yellow
    Write-Host "    Note: First compilation may take 30-60 seconds" -ForegroundColor Gray
    $allGood = $false
}

# Check MCP Server (use /health endpoint)
Write-Host "`n[4] Checking MCP Server..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:9000/health" -TimeoutSec 5 -ErrorAction Stop
    if ($response.StatusCode -eq 200) {
        Write-Host "  [OK] MCP Server is running" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] MCP Server returned status $($response.StatusCode)" -ForegroundColor Red
        $allGood = $false
    }
} catch {
    Write-Host "  [FAIL] MCP Server not responding on port 9000" -ForegroundColor Red
    Write-Host "    Error: $_" -ForegroundColor Gray
    Write-Host "    Start with: cd sentinel_core\mcp; python -m uvicorn src.mcp_server:app --host 0.0.0.0 --port 9000" -ForegroundColor Yellow
    $allGood = $false
}

# Check Database Connection
Write-Host "`n[5] Checking Database Connection..." -ForegroundColor Yellow
try {
    if ($env:PGPASSWORD) {
        $pgBinPath = "C:\Program Files\PostgreSQL\18\bin"
        if ($env:PATH -notlike "*$pgBinPath*") {
            $env:PATH = "$pgBinPath;$env:PATH"
        }
        $result = psql -U postgres -d sentinel_interceptor -c "SELECT COUNT(*) FROM customers;" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Database connection successful" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Database connection failed" -ForegroundColor Red
            Write-Host "    Error: $result" -ForegroundColor Gray
            $allGood = $false
        }
    } else {
        Write-Host "  [SKIP] PGPASSWORD not set, skipping database connection test" -ForegroundColor Yellow
        Write-Host "    Set PGPASSWORD environment variable to test connection" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [SKIP] Could not verify database (psql may not be in PATH)" -ForegroundColor Yellow
    Write-Host "    Error: $_" -ForegroundColor Gray
}

Write-Host "`n=== Verification Complete ===" -ForegroundColor Cyan
if ($allGood) {
    Write-Host "All services are running!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some services are not running. Check errors above." -ForegroundColor Red
    exit 1
}

