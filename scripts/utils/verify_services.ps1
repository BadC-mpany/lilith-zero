# verify_services.ps1
Write-Host "=== Sentinel Integration Verification ===" -ForegroundColor Cyan

# Health check cache (5 second TTL)
$script:healthCache = @{}

function Get-CachedHealthCheck {
    param(
        [string]$url,
        [int]$cacheSeconds = 5,
        [int]$timeoutSec = 5
    )
    $cacheKey = $url
    $now = Get-Date
    
    if ($script:healthCache.ContainsKey($cacheKey)) {
        $cached = $script:healthCache[$cacheKey]
        $age = ($now - $cached.Timestamp).TotalSeconds
        if ($age -lt $cacheSeconds) {
            return $cached.Result
        }
    }
    
    # Perform actual check
    try {
        $result = Invoke-WebRequest -Uri $url -TimeoutSec $timeoutSec -ErrorAction Stop
        $script:healthCache[$cacheKey] = @{
            Timestamp = $now
            Result = $result
        }
        return $result
    } catch {
        # Cache failures too (but with shorter TTL)
        $script:healthCache[$cacheKey] = @{
            Timestamp = $now
            Result = $null
            Error = $_
        }
        throw
    }
}

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
                Write-Host "    Start with: .\scripts\start_all.ps1 or .\scripts\backend\start_redis_docker.ps1" -ForegroundColor Yellow
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
    $response = Get-CachedHealthCheck -url "http://localhost:8000/health" -timeoutSec 5
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
    $response = Get-CachedHealthCheck -url "http://localhost:9000/health" -timeoutSec 5
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
    $dbConnected = $false
    
    # Try parsing DATABASE_URL first
    if ($env:DATABASE_URL) {
        # Parse DATABASE_URL: postgresql://user:password@host:port/database
        if ($env:DATABASE_URL -match 'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)') {
            $dbUser = $matches[1]
            $dbPassword = $matches[2]
            $dbHost = $matches[3]
            $dbPort = $matches[4]
            $dbName = $matches[5]
            
            # Set PGPASSWORD temporarily (don't display password)
            $env:PGPASSWORD = $dbPassword
            
            $pgBinPath = "C:\Program Files\PostgreSQL\18\bin"
            if ($env:PATH -notlike "*$pgBinPath*") {
                $env:PATH = "$pgBinPath;$env:PATH"
            }
            
            $result = psql -h $dbHost -p $dbPort -U $dbUser -d $dbName -c "SELECT 1;" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [OK] Database connection successful (from DATABASE_URL)" -ForegroundColor Green
                $dbConnected = $true
            } else {
                Write-Host "  [FAIL] Database connection failed (from DATABASE_URL)" -ForegroundColor Red
                Write-Host "    Error: $result" -ForegroundColor Gray
                $allGood = $false
            }
            
            # Clear password from environment
            Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
        } else {
            Write-Host "  [SKIP] DATABASE_URL format not recognized" -ForegroundColor Yellow
            Write-Host "    Expected format: postgresql://user:password@host:port/database" -ForegroundColor Gray
        }
    }
    
    # Fallback to PGPASSWORD method if DATABASE_URL not used or failed
    if (-not $dbConnected -and $env:PGPASSWORD) {
        $pgBinPath = "C:\Program Files\PostgreSQL\18\bin"
        if ($env:PATH -notlike "*$pgBinPath*") {
            $env:PATH = "$pgBinPath;$env:PATH"
        }
        $result = psql -U postgres -d sentinel_interceptor -c "SELECT COUNT(*) FROM customers;" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Database connection successful (from PGPASSWORD)" -ForegroundColor Green
            $dbConnected = $true
        } else {
            Write-Host "  [FAIL] Database connection failed" -ForegroundColor Red
            Write-Host "    Error: $result" -ForegroundColor Gray
            $allGood = $false
        }
    }
    
    if (-not $dbConnected) {
        Write-Host "  [SKIP] Database connection not tested" -ForegroundColor Yellow
        Write-Host "    Set DATABASE_URL or PGPASSWORD environment variable to test connection" -ForegroundColor Gray
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

