# auto_fix_redis.ps1
# Automatic Redis connection fix - runs before interceptor startup
# This ensures Redis is always reachable before the Rust app starts

param(
    [switch]$SkipPortForwarding,
    [switch]$SkipRedisConfig
)

Write-Host "`n=== Automatic Redis Connection Fix ===" -ForegroundColor Cyan

# Check admin privileges for port forwarding
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Step 1: Get WSL IP
Write-Host "[1] Getting WSL IP..." -ForegroundColor Yellow
$wsl_ip = (wsl hostname -I 2>&1).Trim().Split(" ")[0]

if (-not $wsl_ip -or $wsl_ip -match "error|not found") {
    Write-Host "  [FAIL] WSL is not running" -ForegroundColor Red
    Write-Host "  Starting WSL..." -ForegroundColor Yellow
    wsl --distribution Ubuntu --exec echo "WSL started" 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    $wsl_ip = (wsl hostname -I 2>&1).Trim().Split(" ")[0]
    
    if (-not $wsl_ip) {
        Write-Host "  [FAIL] Could not get WSL IP" -ForegroundColor Red
        exit 1
    }
}

Write-Host "  [OK] WSL IP: $wsl_ip" -ForegroundColor Green

# Step 2: Ensure Redis is running in WSL
Write-Host "`n[2] Checking Redis in WSL..." -ForegroundColor Yellow
$redis_check = wsl redis-cli ping 2>&1
if ($redis_check -match "PONG") {
    Write-Host "  [OK] Redis is running" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Redis not responding, attempting to start..." -ForegroundColor Yellow
    wsl sudo service redis-server start 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    $redis_check = wsl redis-cli ping 2>&1
    if ($redis_check -match "PONG") {
        Write-Host "  [OK] Redis started successfully" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Redis failed to start" -ForegroundColor Red
        exit 1
    }
}

# Step 3: Verify Redis binding (must be 0.0.0.0)
Write-Host "`n[3] Verifying Redis binding..." -ForegroundColor Yellow
$bind_test = wsl redis-cli -h $wsl_ip ping 2>&1
if ($bind_test -match "PONG") {
    Write-Host "  [OK] Redis accepts connections on WSL IP (bound to 0.0.0.0)" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Redis may not be bound to 0.0.0.0" -ForegroundColor Yellow
    if (-not $SkipRedisConfig) {
        Write-Host "  Attempting to fix Redis binding..." -ForegroundColor Yellow
        wsl bash -c "sudo sed -i 's/^bind 127\.0\.0\.1 ::1/bind 0.0.0.0/' /etc/redis/redis.conf 2>/dev/null; sudo service redis-server restart 2>&1" | Out-Null
        Start-Sleep -Seconds 2
        $bind_test = wsl redis-cli -h $wsl_ip ping 2>&1
        if ($bind_test -match "PONG") {
            Write-Host "  [OK] Redis binding fixed" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Could not fix Redis binding automatically" -ForegroundColor Red
        }
    }
}

# Step 4: Fix port forwarding (if admin and not skipped)
if ($isAdmin -and -not $SkipPortForwarding) {
    Write-Host "`n[4] Checking port forwarding..." -ForegroundColor Yellow
    $forwarding = netsh interface portproxy show all 2>&1 | Select-String "6379"
    
    $needs_fix = $false
    if (-not $forwarding) {
        Write-Host "  [WARN] No port forwarding found" -ForegroundColor Yellow
        $needs_fix = $true
    } elseif ($forwarding -notmatch $wsl_ip) {
        Write-Host "  [WARN] Port forwarding IP mismatch" -ForegroundColor Yellow
        $needs_fix = $true
    }
    
    if ($needs_fix) {
        Write-Host "  Fixing port forwarding..." -ForegroundColor Yellow
        netsh interface portproxy delete v4tov4 listenport=6379 listenaddress=127.0.0.1 2>&1 | Out-Null
        netsh interface portproxy delete v4tov4 listenport=6379 listenaddress=0.0.0.0 2>&1 | Out-Null
        netsh interface portproxy add v4tov4 listenport=6379 listenaddress=127.0.0.1 connectport=6379 connectaddress=$wsl_ip 2>&1 | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Port forwarding updated: 127.0.0.1:6379 -> $wsl_ip`:6379" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Failed to update port forwarding (run as admin)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [OK] Port forwarding is correct" -ForegroundColor Green
    }
} elseif (-not $isAdmin) {
    Write-Host "`n[4] Skipping port forwarding (not running as admin)" -ForegroundColor Yellow
    Write-Host "  Run as admin to auto-fix port forwarding" -ForegroundColor Gray
}

# Step 5: Test actual connection path (what Rust app uses)
Write-Host "`n[5] Testing connection path (127.0.0.1:6379)..." -ForegroundColor Yellow
$connection_test = wsl bash -c "timeout 3 redis-cli -h 127.0.0.1 ping 2>&1 || echo 'TIMEOUT'" 2>&1
if ($connection_test -match "PONG") {
    Write-Host "  [OK] Redis reachable via Windows port forwarding!" -ForegroundColor Green
    Write-Host "  Rust interceptor should be able to connect" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Redis not reachable via port forwarding: $connection_test" -ForegroundColor Red
    Write-Host "  This is the path Rust app uses - connection will fail" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== Redis Connection Fix Complete ===" -ForegroundColor Green
Write-Host "Redis is ready for interceptor connection" -ForegroundColor Green

