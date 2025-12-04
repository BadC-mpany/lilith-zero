# configure_wsl_resources.ps1
# Permanently configure WSL2 resource limits to prevent memory exhaustion

Write-Host "=== WSL2 Resource Configuration ===" -ForegroundColor Cyan
Write-Host "This script configures WSL2 to use limited resources" -ForegroundColor Gray
Write-Host "to prevent 'Insufficient system resources' errors" -ForegroundColor Gray
Write-Host ""

# Check if running as admin (needed for some operations)
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Get system memory
$os = Get-CimInstance Win32_OperatingSystem
$totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)

# Calculate safe WSL memory limit (use max 25% of total RAM, min 2GB, max 4GB)
$wslMemoryGB = [math]::Max(2, [math]::Min(4, [math]::Floor($totalGB * 0.25)))
$wslMemoryMB = $wslMemoryGB * 1024

Write-Host "[1] System Analysis:" -ForegroundColor Yellow
Write-Host "  Total RAM: $totalGB GB" -ForegroundColor Cyan
Write-Host "  Recommended WSL Memory: $wslMemoryGB GB ($wslMemoryMB MB)" -ForegroundColor Green
Write-Host ""

# Create .wslconfig file
Write-Host "[2] Creating .wslconfig file..." -ForegroundColor Yellow
$wslConfigPath = "$env:USERPROFILE\.wslconfig"
$wslConfigContent = @"
# WSL2 Resource Configuration
# Prevents "Insufficient system resources" errors by limiting WSL memory usage
# This file is automatically managed - do not edit manually

[wsl2]
# Memory limit (prevents WSL from consuming all system RAM)
memory=$wslMemoryMB`MB

# Number of processors (limit to prevent CPU exhaustion)
processors=2

# Swap file size (virtual memory for WSL)
swap=$($wslMemoryGB * 512)`MB

# Swap file location
swapFile=C:\\Users\\$env:USERNAME\\AppData\\Local\\Temp\\swap.vhdx

# Enable localhost forwarding (required for Redis port forwarding)
localhostForwarding=true

# Disable nested virtualization (reduces resource usage)
nestedVirtualization=false

# Kernel command line arguments for better resource management
kernelCommandLine=systemd.unified_cgroup_hierarchy=1
"@

try {
    $wslConfigContent | Out-File -FilePath $wslConfigPath -Encoding UTF8 -NoNewline
    Write-Host "  [OK] .wslconfig created at: $wslConfigPath" -ForegroundColor Green
    
    Write-Host "`nConfiguration:" -ForegroundColor Cyan
    Write-Host "  Memory Limit: $wslMemoryGB GB" -ForegroundColor White
    Write-Host "  Processors: 2" -ForegroundColor White
    Write-Host "  Swap: $($wslMemoryGB * 512) MB" -ForegroundColor White
    Write-Host "  Localhost Forwarding: Enabled" -ForegroundColor White
} catch {
    Write-Host "  [FAIL] Failed to create .wslconfig: $_" -ForegroundColor Red
    exit 1
}

# Shutdown WSL to apply configuration
Write-Host "`n[3] Applying configuration..." -ForegroundColor Yellow
Write-Host "  Shutting down WSL..." -ForegroundColor Gray
wsl --shutdown 2>&1 | Out-Null

Write-Host "  [OK] WSL shutdown complete" -ForegroundColor Green
Write-Host "  Waiting 10 seconds for cleanup..." -ForegroundColor Gray
Start-Sleep -Seconds 10

# Verify WSL can start
Write-Host "`n[4] Verifying WSL starts correctly..." -ForegroundColor Yellow
try {
    $testResult = wsl echo "WSL is working" 2>&1
    if ($testResult -like "*WSL is working*") {
        Write-Host "  [OK] WSL started successfully" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] WSL response: $testResult" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [WARN] Could not verify WSL startup: $_" -ForegroundColor Yellow
    Write-Host "    Try manually: wsl echo test" -ForegroundColor Gray
}

Write-Host "`n=== Configuration Complete ===" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "1. Restart WSL: wsl --shutdown (wait 10s) then wsl redis-cli ping" -ForegroundColor White
Write-Host "2. Verify Redis: wsl redis-cli ping" -ForegroundColor White
Write-Host "3. Start interceptor: .\scripts\start_all.ps1" -ForegroundColor White
Write-Host "`nNote: WSL will now use max $wslMemoryGB GB RAM (prevents resource exhaustion)" -ForegroundColor Cyan

