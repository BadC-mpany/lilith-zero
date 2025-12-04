# wsl_health_check.ps1
# Health check and auto-recovery for WSL Redis

param(
    [switch]$AutoRecover
)

Write-Host "=== WSL Health Check ===" -ForegroundColor Cyan

$wslHealthy = $false
$redisHealthy = $false

# Check WSL availability
Write-Host "`n[1] Checking WSL availability..." -ForegroundColor Yellow
try {
    $wslTest = wsl echo "test" 2>&1
    if ($LASTEXITCODE -eq 0 -and $wslTest -like "*test*") {
        Write-Host "  [OK] WSL is running" -ForegroundColor Green
        $wslHealthy = $true
    } else {
        Write-Host "  [FAIL] WSL not responding" -ForegroundColor Red
        Write-Host "    Error: $wslTest" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [FAIL] WSL error: $_" -ForegroundColor Red
    $wslHealthy = $false
}

# Check Redis
if ($wslHealthy) {
    Write-Host "`n[2] Checking Redis..." -ForegroundColor Yellow
    try {
        $redisTest = wsl redis-cli ping 2>&1
        if ($redisTest -eq "PONG") {
            Write-Host "  [OK] Redis is running" -ForegroundColor Green
            $redisHealthy = $true
        } else {
            Write-Host "  [FAIL] Redis not responding: $redisTest" -ForegroundColor Red
        }
    } catch {
        Write-Host "  [FAIL] Redis check failed: $_" -ForegroundColor Red
    }
} else {
    Write-Host "`n[2] Skipping Redis check (WSL not available)" -ForegroundColor Yellow
}

# Auto-recovery if enabled
if ($AutoRecover -and -not $wslHealthy) {
    Write-Host "`n[3] Attempting auto-recovery..." -ForegroundColor Yellow
    Write-Host "  Shutting down WSL..." -ForegroundColor Gray
    wsl --shutdown 2>&1 | Out-Null
    Start-Sleep -Seconds 10
    
    Write-Host "  Testing WSL startup..." -ForegroundColor Gray
    try {
        $recoveryTest = wsl echo "recovery" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] WSL recovered" -ForegroundColor Green
            $wslHealthy = $true
            
            # Try to start Redis if WSL recovered
            Write-Host "  Starting Redis..." -ForegroundColor Gray
            wsl redis-server --daemonize yes 2>&1 | Out-Null
            Start-Sleep -Seconds 2
            
            $redisTest = wsl redis-cli ping 2>&1
            if ($redisTest -eq "PONG") {
                Write-Host "  [OK] Redis started" -ForegroundColor Green
                $redisHealthy = $true
            }
        }
    } catch {
        Write-Host "  [FAIL] Recovery failed: $_" -ForegroundColor Red
    }
}

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
if ($wslHealthy -and $redisHealthy) {
    Write-Host "All systems healthy!" -ForegroundColor Green
    exit 0
} elseif ($wslHealthy) {
    Write-Host "WSL is running but Redis is not" -ForegroundColor Yellow
    Write-Host "  Start Redis: wsl redis-server --daemonize yes" -ForegroundColor White
    exit 1
} else {
    Write-Host "WSL is not available" -ForegroundColor Red
    Write-Host "  Run: wsl --shutdown (wait 10s) then try again" -ForegroundColor White
    Write-Host "  Or configure resources: .\scripts\configure_wsl_resources.ps1" -ForegroundColor White
    exit 1
}

