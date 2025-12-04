# check_redis_availability.ps1
# Intelligently checks Redis availability and suggests the best option

Write-Host "=== Redis Availability Check ===" -ForegroundColor Cyan

$redisAvailable = $false
$redisSource = ""
$redisUrl = ""

# Check WSL Redis
Write-Host "`n[1] Checking WSL Redis..." -ForegroundColor Yellow
try {
    $wslResult = wsl redis-cli ping 2>&1
    if ($wslResult -eq "PONG") {
        Write-Host "  [OK] WSL Redis is running" -ForegroundColor Green
        $redisAvailable = $true
        $redisSource = "WSL"
        $redisUrl = "redis://localhost:6379/0"
        
        # Verify port forwarding
        $forwarding = netsh interface portproxy show all 2>&1 | Select-String "6379"
        if ($forwarding) {
            Write-Host "  [OK] Port forwarding configured" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] Port forwarding not configured" -ForegroundColor Yellow
            Write-Host "    Run: .\scripts\setup_wsl_redis_forwarding.ps1" -ForegroundColor Gray
        }
    } else {
        Write-Host "  [FAIL] WSL Redis not responding: $wslResult" -ForegroundColor Red
    }
} catch {
    Write-Host "  [FAIL] WSL not available or Redis not running" -ForegroundColor Red
    Write-Host "    Error: $_" -ForegroundColor Gray
}

# Note: Using WSL Redis only (Memurai check removed per user preference)

# Test direct TCP connection
Write-Host "`n[3] Testing TCP connection to localhost:6379..." -ForegroundColor Yellow
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $result = $tcpClient.BeginConnect("127.0.0.1", 6379, $null, $null)
    $wait = $result.AsyncWaitHandle.WaitOne(2000, $false)
    if ($wait) {
        $tcpClient.EndConnect($result)
        Write-Host "  [OK] TCP connection successful" -ForegroundColor Green
        $tcpClient.Close()
    } else {
        Write-Host "  [FAIL] TCP connection timed out" -ForegroundColor Red
        $tcpClient.Close()
    }
} catch {
    Write-Host "  [FAIL] TCP connection failed: $_" -ForegroundColor Red
}

# Summary and recommendations
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
if ($redisAvailable) {
    Write-Host "Redis is available via: $redisSource" -ForegroundColor Green
    Write-Host "Recommended REDIS_URL: $redisUrl" -ForegroundColor Cyan
    Write-Host "`nCurrent .env configuration:" -ForegroundColor Yellow
    $envFile = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) "sentinel_core\interceptor\rust\.env"
    if (Test-Path $envFile) {
        $redisLine = Get-Content $envFile | Select-String "REDIS_URL"
        if ($redisLine) {
            Write-Host "  $redisLine" -ForegroundColor Gray
        } else {
            Write-Host "  REDIS_URL not found in .env" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  .env file not found" -ForegroundColor Yellow
    }
} else {
    Write-Host "WSL Redis is not available!" -ForegroundColor Red
    Write-Host "`nFix steps:" -ForegroundColor Yellow
    Write-Host "1. Start WSL Redis: wsl redis-server --daemonize yes" -ForegroundColor White
    Write-Host "2. Configure port forwarding: .\scripts\setup_wsl_redis_forwarding.ps1" -ForegroundColor White
    Write-Host "3. If WSL won't start, run: wsl --shutdown (wait 30s) then try again" -ForegroundColor White
    Write-Host "4. Verify: wsl redis-cli ping" -ForegroundColor White
}

exit $(if ($redisAvailable) { 0 } else { 1 })

