# diagnose_redis_connection.ps1
# Comprehensive Redis connection diagnostics
# Tests actual Redis connectivity, not just TCP handshake

Write-Host "`n=== Redis Connection Diagnostics ===" -ForegroundColor Cyan
Write-Host ""

# Test 1: WSL IP
Write-Host "[1] WSL IP Address" -ForegroundColor Yellow
$wsl_ip = (wsl hostname -I).Trim().Split(" ")[0]
if ($wsl_ip) {
    Write-Host "  Current WSL IP: $wsl_ip" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] WSL not running or IP not found" -ForegroundColor Red
    exit 1
}

# Test 2: Port Forwarding
Write-Host "`n[2] Port Forwarding Configuration" -ForegroundColor Yellow
$forwarding = netsh interface portproxy show all | Select-String "6379"
if ($forwarding) {
    Write-Host "  Active forwarding:" -ForegroundColor White
    Write-Host "    $forwarding" -ForegroundColor Gray
    
    # Parse port forwarding format: listenaddress listenport connectaddress connectport
    # Example: "127.0.0.1       6379        172.27.192.10   6379"
    # We need the connectaddress (3rd field), not listenaddress (1st field)
    if ($forwarding -match "(\d+\.\d+\.\d+\.\d+)\s+6379\s+(\d+\.\d+\.\d+\.\d+)\s+6379") {
        $listen_ip = $matches[1]
        $forwarded_ip = $matches[2]  # This is the connectaddress (where it forwards TO)
        Write-Host "  Listen address: $listen_ip:6379" -ForegroundColor Gray
        Write-Host "  Forward to: $forwarded_ip:6379" -ForegroundColor Gray
        
        if ($forwarded_ip -eq $wsl_ip) {
            Write-Host "  [OK] Forwarding IP matches current WSL IP" -ForegroundColor Green
        } else {
            Write-Host "  [ISSUE] Forwarding points to old IP: $forwarded_ip" -ForegroundColor Red
            Write-Host "          Current WSL IP: $wsl_ip" -ForegroundColor Yellow
        }
    } elseif ($forwarding -match "(\d+\.\d+\.\d+\.\d+)\s+6379") {
        # Fallback: if format doesn't match expected, just extract first IP (old behavior)
        $forwarded_ip = $matches[1]
        Write-Host "  [WARN] Could not parse forwarding format correctly" -ForegroundColor Yellow
        Write-Host "  Extracted IP: $forwarded_ip" -ForegroundColor Gray
    }
} else {
    Write-Host "  [FAIL] No port forwarding configured for port 6379" -ForegroundColor Red
    $forwarded_ip = $null
}

# Test 3: Redis Direct Connection (from WSL)
Write-Host "`n[3] Redis Direct Connection Test (from WSL)" -ForegroundColor Yellow
$direct_ping = wsl redis-cli ping 2>&1
if ($direct_ping -match "PONG") {
    Write-Host "  [OK] Redis is running and responding" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Redis not responding: $direct_ping" -ForegroundColor Red
    Write-Host "  Start Redis: wsl redis-server --daemonize yes" -ForegroundColor Yellow
}

# Test 4: Redis Binding Test (via WSL IP)
Write-Host "`n[4] Redis Binding Test (connection via WSL IP)" -ForegroundColor Yellow
Write-Host "  Testing if Redis accepts connections on WSL IP ($wsl_ip)..." -ForegroundColor Gray
$ip_ping = wsl redis-cli -h $wsl_ip ping 2>&1
if ($ip_ping -match "PONG") {
    Write-Host "  [OK] Redis accepts connections on WSL IP (bound to 0.0.0.0)" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Redis does not accept connections on WSL IP" -ForegroundColor Red
    Write-Host "  Likely cause: Redis bound to 127.0.0.1 only" -ForegroundColor Yellow
    Write-Host "  Fix: Change 'bind 127.0.0.1' to 'bind 0.0.0.0' in /etc/redis/redis.conf" -ForegroundColor Yellow
}

# Test 5: Windows Port Forwarding Test (CRITICAL - what Rust app uses)
Write-Host "`n[5] Windows Port Forwarding Test (CRITICAL)" -ForegroundColor Yellow
Write-Host "  This tests the actual path Rust app uses: 127.0.0.1:6379" -ForegroundColor Gray
Write-Host "  (This is NOT just TCP handshake - it tests actual Redis response)" -ForegroundColor DarkGray

# Use WSL redis-cli connecting to Windows localhost (goes through port forwarding)
$forwarded_ping = wsl bash -c "timeout 3 redis-cli -h 127.0.0.1 ping 2>&1 || echo 'TIMEOUT_OR_ERROR'"
if ($forwarded_ping -match "PONG") {
    Write-Host "  [OK] Redis reachable via Windows port forwarding!" -ForegroundColor Green
    Write-Host "  Rust app should be able to connect successfully" -ForegroundColor Green
} elseif ($forwarded_ping -match "TIMEOUT") {
    Write-Host "  [FAIL] Connection timeout via port forwarding" -ForegroundColor Red
    Write-Host "  Possible causes:" -ForegroundColor Yellow
    Write-Host "    1. Port forwarding IP mismatch (run fix script)" -ForegroundColor Gray
    Write-Host "    2. Redis not bound to 0.0.0.0 (run fix script)" -ForegroundColor Gray
    Write-Host "    3. WSL firewall blocking forwarded connections" -ForegroundColor Gray
} else {
    Write-Host "  [FAIL] Connection error via port forwarding: $forwarded_ping" -ForegroundColor Red
}

# Test 6: TCP Connection Test (for comparison - shows false positive)
Write-Host "`n[6] TCP Connection Test (for comparison)" -ForegroundColor Yellow
Write-Host "  Note: This only tests TCP handshake, NOT Redis response" -ForegroundColor DarkGray
try {
    $tcp_test = Test-NetConnection -ComputerName 127.0.0.1 -Port 6379 -WarningAction SilentlyContinue
    if ($tcp_test.TcpTestSucceeded) {
        Write-Host "  [OK] TCP connection succeeds (but this doesn't mean Redis responds!)" -ForegroundColor Yellow
        Write-Host "  This is why Test-NetConnection can give false positives" -ForegroundColor DarkGray
    } else {
        Write-Host "  [FAIL] TCP connection failed" -ForegroundColor Red
    }
} catch {
    Write-Host "  [FAIL] TCP test error: $_" -ForegroundColor Red
}

# Summary
Write-Host "`n=== Diagnostic Summary ===" -ForegroundColor Cyan
Write-Host ""

$all_ok = $true
if (-not ($direct_ping -match "PONG")) {
    Write-Host "[ISSUE] Redis not running or not responding" -ForegroundColor Red
    $all_ok = $false
}
if (-not ($ip_ping -match "PONG")) {
    Write-Host "[ISSUE] Redis binding issue - not accepting connections on WSL IP" -ForegroundColor Red
    $all_ok = $false
}
if (-not ($forwarded_ping -match "PONG")) {
    Write-Host "[ISSUE] Port forwarding not working correctly" -ForegroundColor Red
    $all_ok = $false
}
if ($forwarding -and $forwarded_ip -and $forwarded_ip -ne $wsl_ip) {
    Write-Host "[ISSUE] Port forwarding IP mismatch" -ForegroundColor Red
    $all_ok = $false
}

if ($all_ok) {
    Write-Host "[OK] All tests passed - Redis should be reachable from Rust app" -ForegroundColor Green
} else {
    Write-Host "[ACTION REQUIRED] Issues detected - run fix script:" -ForegroundColor Yellow
    Write-Host "  .\scripts\fix_wsl_redis_connection.ps1" -ForegroundColor White
}

