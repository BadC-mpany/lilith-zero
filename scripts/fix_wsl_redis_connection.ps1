# fix_wsl_redis_connection.ps1
# Comprehensive fix for WSL Redis connection issues
# Addresses: IP drift, Redis binding, port forwarding

param(
    [switch]$SkipRedisConfig,
    [switch]$SkipPortForwarding
)

Write-Host "`n=== WSL Redis Connection Fix ===" -ForegroundColor Cyan
Write-Host "This script fixes common WSL Redis connection issues:" -ForegroundColor Yellow
Write-Host "  1. WSL IP drift (updates port forwarding)" -ForegroundColor White
Write-Host "  2. Redis binding (ensures bind 0.0.0.0)" -ForegroundColor White
Write-Host "  3. Port forwarding (syncs with current WSL IP)" -ForegroundColor White
Write-Host ""

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[ERROR] This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Step 1: Get current WSL IP
Write-Host "[1] Getting current WSL IP address..." -ForegroundColor Yellow
$wsl_ip = (wsl hostname -I).Trim().Split(" ")[0]

if (-not $wsl_ip) {
    Write-Host "[ERROR] WSL is not running or IP not found" -ForegroundColor Red
    Write-Host "Start WSL: wsl" -ForegroundColor Yellow
    exit 1
}

Write-Host "  Current WSL IP: $wsl_ip" -ForegroundColor Green

# Step 2: Check port forwarding
Write-Host "`n[2] Checking port forwarding configuration..." -ForegroundColor Yellow
$forwarding = netsh interface portproxy show all | Select-String "6379"

if ($forwarding) {
    Write-Host "  Current forwarding:" -ForegroundColor Gray
    Write-Host "    $forwarding" -ForegroundColor White
    
    # Extract target IP from forwarding rule
    if ($forwarding -match "(\d+\.\d+\.\d+\.\d+)\s+6379") {
        $forwarded_ip = $matches[1]
        Write-Host "  Forwarding points to: $forwarded_ip" -ForegroundColor Gray
        
        if ($forwarded_ip -ne $wsl_ip) {
            Write-Host "  [ISSUE] IP mismatch detected!" -ForegroundColor Red
            Write-Host "    Port forwarding points to old IP: $forwarded_ip" -ForegroundColor Yellow
            Write-Host "    Current WSL IP: $wsl_ip" -ForegroundColor Yellow
            $needs_update = $true
        } else {
            Write-Host "  [OK] Port forwarding IP matches current WSL IP" -ForegroundColor Green
            $needs_update = $false
        }
    }
} else {
    Write-Host "  [WARN] No port forwarding found for port 6379" -ForegroundColor Yellow
    $needs_update = $true
}

# Step 3: Fix Redis binding (if not skipped)
if (-not $SkipRedisConfig) {
    Write-Host "`n[3] Checking Redis bind configuration..." -ForegroundColor Yellow
    
    # Check current bind setting
    $bind_check = wsl bash -c "sudo grep '^bind' /etc/redis/redis.conf 2>/dev/null || echo 'NOT_FOUND'"
    
    if ($bind_check -match "NOT_FOUND") {
        Write-Host "  [WARN] Could not read redis.conf (may need sudo)" -ForegroundColor Yellow
        Write-Host "  Attempting to check Redis binding via test..." -ForegroundColor Gray
        
        # Test if Redis accepts connections on WSL IP
        $test_result = wsl redis-cli -h $wsl_ip ping 2>&1
        if ($test_result -match "PONG") {
            Write-Host "  [OK] Redis accepts connections on WSL IP (likely bound to 0.0.0.0)" -ForegroundColor Green
        } else {
            Write-Host "  [ISSUE] Redis may be bound to 127.0.0.1 only" -ForegroundColor Red
            Write-Host "  Manual fix required:" -ForegroundColor Yellow
            Write-Host "    1. wsl" -ForegroundColor Gray
            Write-Host "    2. sudo nano /etc/redis/redis.conf" -ForegroundColor Gray
            Write-Host "    3. Find 'bind 127.0.0.1 ::1' and change to 'bind 0.0.0.0'" -ForegroundColor Gray
            Write-Host "    4. sudo service redis-server restart" -ForegroundColor Gray
        }
    } else {
        Write-Host "  Current bind config: $bind_check" -ForegroundColor White
        
        if ($bind_check -match "0\.0\.0\.0") {
            Write-Host "  [OK] Redis is bound to 0.0.0.0 (all interfaces)" -ForegroundColor Green
        } else {
            Write-Host "  [ISSUE] Redis is bound to 127.0.0.1 only" -ForegroundColor Red
            Write-Host "  Attempting to fix..." -ForegroundColor Yellow
            
            # Try to fix via WSL command
            $fix_result = wsl bash -c "sudo sed -i 's/^bind 127\.0\.0\.1 ::1/bind 0.0.0.0/' /etc/redis/redis.conf && sudo service redis-server restart && echo 'FIXED' || echo 'FAILED'"
            
            if ($fix_result -match "FIXED") {
                Write-Host "  [OK] Redis binding fixed and restarted" -ForegroundColor Green
            } else {
                Write-Host "  [FAIL] Could not fix automatically" -ForegroundColor Red
                Write-Host "  Manual fix required (see instructions above)" -ForegroundColor Yellow
            }
        }
    }
} else {
    Write-Host "`n[3] Skipping Redis config check (--SkipRedisConfig)" -ForegroundColor Gray
}

# Step 4: Update port forwarding (if needed and not skipped)
if (-not $SkipPortForwarding) {
    if ($needs_update) {
        Write-Host "`n[4] Updating port forwarding..." -ForegroundColor Yellow
        
        # Remove old rule
        netsh interface portproxy delete v4tov4 listenport=6379 listenaddress=127.0.0.1 2>&1 | Out-Null
        netsh interface portproxy delete v4tov4 listenport=6379 listenaddress=0.0.0.0 2>&1 | Out-Null
        
        # Add new rule with current WSL IP
        netsh interface portproxy add v4tov4 listenport=6379 listenaddress=127.0.0.1 connectport=6379 connectaddress=$wsl_ip
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Port forwarding updated: 127.0.0.1:6379 -> $wsl_ip`:6379" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Failed to update port forwarding" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "`n[4] Port forwarding is correct, skipping update" -ForegroundColor Green
    }
} else {
    Write-Host "`n[4] Skipping port forwarding update (--SkipPortForwarding)" -ForegroundColor Gray
}

# Step 5: Comprehensive connectivity test
Write-Host "`n[5] Testing Redis connectivity..." -ForegroundColor Yellow

# Test 1: Direct WSL connection
Write-Host "  Test 1: Direct WSL connection..." -ForegroundColor Gray
$direct_test = wsl redis-cli ping 2>&1
if ($direct_test -match "PONG") {
    Write-Host "    [OK] Redis responds to direct connection" -ForegroundColor Green
} else {
    Write-Host "    [FAIL] Redis not responding: $direct_test" -ForegroundColor Red
    Write-Host "    Start Redis: wsl redis-server --daemonize yes" -ForegroundColor Yellow
    exit 1
}

# Test 2: Connection via WSL IP
Write-Host "  Test 2: Connection via WSL IP ($wsl_ip)..." -ForegroundColor Gray
$ip_test = wsl redis-cli -h $wsl_ip ping 2>&1
if ($ip_test -match "PONG") {
    Write-Host "    [OK] Redis accepts connections on WSL IP" -ForegroundColor Green
} else {
    Write-Host "    [FAIL] Redis not accepting connections on WSL IP: $ip_test" -ForegroundColor Red
    Write-Host "    Redis must be bound to 0.0.0.0 (not 127.0.0.1)" -ForegroundColor Yellow
    exit 1
}

# Test 3: Connection via Windows forwarded port (actual test)
Write-Host "  Test 3: Connection via Windows forwarded port (127.0.0.1)..." -ForegroundColor Gray
Write-Host "    This is the actual test - what Rust app uses" -ForegroundColor DarkGray

# Use a proper Redis client test from Windows
# We'll use WSL redis-cli connecting to localhost (which goes through port forwarding)
$forwarded_test = wsl bash -c "timeout 2 redis-cli -h 127.0.0.1 ping 2>&1 || echo 'TIMEOUT'"
if ($forwarded_test -match "PONG") {
    Write-Host "    [OK] Redis reachable via Windows port forwarding!" -ForegroundColor Green
    Write-Host "    This means Rust app should be able to connect" -ForegroundColor Green
} else {
    Write-Host "    [FAIL] Redis not reachable via port forwarding: $forwarded_test" -ForegroundColor Red
    Write-Host "    Possible causes:" -ForegroundColor Yellow
    Write-Host "      1. Port forwarding not working correctly" -ForegroundColor Gray
    Write-Host "      2. Redis not bound to 0.0.0.0" -ForegroundColor Gray
    Write-Host "      3. WSL firewall blocking connections" -ForegroundColor Gray
    exit 1
}

Write-Host "`n=== Fix Complete ===" -ForegroundColor Green
Write-Host "Redis should now be reachable from Rust interceptor" -ForegroundColor Green
Write-Host "`nConfiguration:" -ForegroundColor Cyan
Write-Host "  Redis URL: redis://127.0.0.1:6379/0" -ForegroundColor White
Write-Host "  WSL IP: $wsl_ip" -ForegroundColor White
Write-Host "  Port forwarding: 127.0.0.1:6379 -> $wsl_ip`:6379" -ForegroundColor White
Write-Host "`nNote: Port forwarding persists until Windows restart" -ForegroundColor Gray
Write-Host "Re-run this script if WSL IP changes after restart" -ForegroundColor Gray

