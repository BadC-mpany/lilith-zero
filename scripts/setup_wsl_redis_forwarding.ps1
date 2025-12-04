# setup_wsl_redis_forwarding.ps1
# Run this script as Administrator to forward Windows localhost:6379 to WSL Redis

Write-Host "=== WSL Redis Port Forwarding Setup ===" -ForegroundColor Cyan
Write-Host "This script requires Administrator privileges" -ForegroundColor Yellow
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[ERROR] This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Get WSL IP
Write-Host "[1] Getting WSL IP address..." -ForegroundColor Yellow
$wslIp = wsl hostname -I | ForEach-Object { $_.Trim() }
if (-not $wslIp) {
    Write-Host "[ERROR] Could not get WSL IP address" -ForegroundColor Red
    exit 1
}
Write-Host "  WSL IP: $wslIp" -ForegroundColor Green

# Remove existing port forwarding (if any)
Write-Host "`n[2] Removing existing port forwarding (if any)..." -ForegroundColor Yellow
netsh interface portproxy delete v4tov4 listenport=6379 listenaddress=127.0.0.1 2>&1 | Out-Null

# Add port forwarding
Write-Host "`n[3] Setting up port forwarding..." -ForegroundColor Yellow
netsh interface portproxy add v4tov4 listenport=6379 listenaddress=127.0.0.1 connectport=6379 connectaddress=$wslIp

if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Port forwarding configured" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Failed to configure port forwarding" -ForegroundColor Red
    exit 1
}

# Verify port forwarding
Write-Host "`n[4] Verifying port forwarding..." -ForegroundColor Yellow
$forwarding = netsh interface portproxy show all | Select-String "6379"
if ($forwarding) {
    Write-Host "  [OK] Port forwarding active:" -ForegroundColor Green
    Write-Host "    $forwarding" -ForegroundColor Gray
} else {
    Write-Host "  [WARN] Port forwarding not found in list" -ForegroundColor Yellow
}

# Test connection
Write-Host "`n[5] Testing Redis connection..." -ForegroundColor Yellow
try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect("127.0.0.1", 6379)
    Write-Host "  [OK] Successfully connected to Redis via localhost:6379" -ForegroundColor Green
    $client.Close()
} catch {
    Write-Host "  [FAIL] Cannot connect: $_" -ForegroundColor Red
    Write-Host "  Make sure Redis is running in WSL: wsl redis-cli ping" -ForegroundColor Yellow
}

Write-Host "`n=== Setup Complete ===" -ForegroundColor Cyan
Write-Host "Redis URL for Rust interceptor: redis://localhost:6379/0" -ForegroundColor Green
Write-Host "`nNote: Port forwarding persists until Windows restart or manual removal" -ForegroundColor Gray
Write-Host "To remove: netsh interface portproxy delete v4tov4 listenport=6379 listenaddress=127.0.0.1" -ForegroundColor Gray

