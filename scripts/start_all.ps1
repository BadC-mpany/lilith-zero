# start_all.ps1
# Start all Sentinel services with proper initialization and verification

param(
    [switch]$SkipVerification
)

Write-Host "=== Starting Sentinel Services ===" -ForegroundColor Cyan

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

# Check WSL health first
Write-Host "`n[0] Checking WSL health..." -ForegroundColor Yellow
$wslCheck = & "$scriptDir\wsl_health_check.ps1" -AutoRecover 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [WARN] WSL health check failed" -ForegroundColor Yellow
    Write-Host "    Run: .\scripts\configure_wsl_resources.ps1 to fix permanently" -ForegroundColor Gray
} else {
    Write-Host "  [OK] WSL and Redis are healthy" -ForegroundColor Green
}

# AUTOMATIC REDIS FIX - CRITICAL: Fix Redis connection BEFORE starting interceptor
Write-Host "`n[0.5] Auto-fixing Redis connection..." -ForegroundColor Yellow
$redisFix = & "$scriptDir\auto_fix_redis.ps1" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Redis connection fixed and verified" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Redis auto-fix failed" -ForegroundColor Red
    Write-Host "  Attempting manual fix..." -ForegroundColor Yellow
    # Try without admin (port forwarding might already be set)
    $redisFix2 = & "$scriptDir\auto_fix_redis.ps1" -SkipPortForwarding 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Redis connection verified (port forwarding may need admin)" -ForegroundColor Yellow
    } else {
        Write-Host "  [WARN] Redis fix failed - interceptor may fail to connect" -ForegroundColor Red
        Write-Host "  Run manually as admin: .\scripts\fix_wsl_redis_connection.ps1" -ForegroundColor Yellow
    }
}

# Start PostgreSQL service
Write-Host "`n[1] Starting PostgreSQL..." -ForegroundColor Yellow
try {
    $pgService = Get-Service | Where-Object { $_.Name -like "postgresql*" } | Select-Object -First 1
    if ($pgService) {
        if ($pgService.Status -eq "Running") {
            Write-Host "  [OK] PostgreSQL already running" -ForegroundColor Green
        } else {
            Start-Service $pgService.Name -ErrorAction Stop
            Write-Host "  [OK] PostgreSQL started" -ForegroundColor Green
        }
    } else {
        Write-Host "  [WARN] PostgreSQL service not found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [WARN] PostgreSQL error: $_" -ForegroundColor Yellow
}

# Start Rust Interceptor (in new window)
Write-Host "`n[2] Starting Rust Interceptor..." -ForegroundColor Yellow
$rustPath = Join-Path $projectRoot "sentinel_core\interceptor\rust"
if (Test-Path $rustPath) {
    # CRITICAL: Auto-fix Redis again right before starting interceptor
    Write-Host "  Pre-flight Redis check..." -ForegroundColor Gray
    $preflight = & "$scriptDir\auto_fix_redis.ps1" -SkipPortForwarding 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [WARN] Pre-flight Redis check failed - interceptor may fail" -ForegroundColor Yellow
    }
    
    $rustCommand = "cd '$rustPath'; Write-Host '=== Rust Interceptor ===' -ForegroundColor Cyan; Write-Host 'Compiling and starting...' -ForegroundColor Gray; cargo run --bin sentinel-interceptor"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $rustCommand
    Write-Host "  [OK] Rust Interceptor window opened" -ForegroundColor Green
    Write-Host "  [INFO] Compilation may take 30-60 seconds on first run" -ForegroundColor Gray
} else {
    Write-Host "  [FAIL] Rust interceptor path not found: $rustPath" -ForegroundColor Red
}

# Start MCP Server (in new window)
Write-Host "`n[3] Starting MCP Server..." -ForegroundColor Yellow
$mcpPath = Join-Path $projectRoot "sentinel_core\mcp"
if (Test-Path $mcpPath) {
    # Check for virtual environment
    $venvPath = Join-Path $projectRoot "sentinel_env"
    $pythonCmd = "python"
    if (Test-Path $venvPath) {
        $pythonCmd = Join-Path $venvPath "Scripts\python.exe"
        if (-not (Test-Path $pythonCmd)) {
            $pythonCmd = "python"  # Fallback if venv python not found
        }
    }
    
    # Build command with error handling
    $mcpCommand = @"
cd '$mcpPath'
Write-Host '=== MCP Server ===' -ForegroundColor Cyan
Write-Host 'Starting on http://0.0.0.0:9000...' -ForegroundColor Gray
`$ErrorActionPreference = 'Stop'
try {
    $pythonCmd -m uvicorn src.mcp_server:app --host 0.0.0.0 --port 9000
} catch {
    Write-Host '[ERROR] MCP Server failed to start' -ForegroundColor Red
    Write-Host `$_.Exception.Message -ForegroundColor Red
    Write-Host '`nTroubleshooting:' -ForegroundColor Yellow
    Write-Host '  1. Check Python is installed: python --version' -ForegroundColor Gray
    Write-Host '  2. Install dependencies: pip install -r requirements.txt' -ForegroundColor Gray
    Write-Host '  3. Check virtual environment is activated' -ForegroundColor Gray
    Write-Host '`nPress any key to exit...' -ForegroundColor Gray
    `$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}
"@
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $mcpCommand
    Write-Host "  [OK] MCP Server window opened" -ForegroundColor Green
    Write-Host "  [INFO] Check the window for startup errors" -ForegroundColor Gray
} else {
    Write-Host "  [FAIL] MCP server path not found: $mcpPath" -ForegroundColor Red
}

Write-Host "`n=== Services Starting ===" -ForegroundColor Green
Write-Host "Rust Interceptor: http://localhost:8000" -ForegroundColor Cyan
Write-Host "MCP Server: http://localhost:9000" -ForegroundColor Cyan

if (-not $SkipVerification) {
    Write-Host "`nWaiting for services to initialize..." -ForegroundColor Yellow
    Write-Host "  (Rust compilation may take 30-60 seconds)" -ForegroundColor Gray
    
    # Wait longer for services to start (especially Rust compilation)
    $maxWait = 90  # Maximum wait time in seconds
    $checkInterval = 5  # Check every 5 seconds
    $elapsed = 0
    $rustReady = $false
    $mcpReady = $false
    
    while ($elapsed -lt $maxWait -and (-not $rustReady -or -not $mcpReady)) {
        Start-Sleep -Seconds $checkInterval
        $elapsed += $checkInterval
        
        # Check Rust Interceptor
        if (-not $rustReady) {
            try {
                $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 2 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) {
                    $rustReady = $true
                    Write-Host "  [OK] Rust Interceptor is ready" -ForegroundColor Green
                }
            } catch {
                # Still waiting
            }
        }
        
        # Check MCP Server
        if (-not $mcpReady) {
            try {
                $response = Invoke-WebRequest -Uri "http://localhost:9000" -TimeoutSec 2 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) {
                    $mcpReady = $true
                    Write-Host "  [OK] MCP Server is ready" -ForegroundColor Green
                }
            } catch {
                # Still waiting
            }
        }
        
        if (-not $rustReady -or -not $mcpReady) {
            Write-Host "  Waiting... ($elapsed/$maxWait seconds)" -ForegroundColor Gray
        }
    }
    
    Write-Host "`nRunning full verification..." -ForegroundColor Yellow
    & "$scriptDir\verify_services.ps1"
}

Write-Host "`n=== Next Steps ===" -ForegroundColor Cyan
Write-Host "To start the conversational agent, run:" -ForegroundColor Yellow
Write-Host "  .\scripts\start_agent.ps1" -ForegroundColor White
Write-Host "`nor manually:" -ForegroundColor Gray
Write-Host "  cd sentinel_agent" -ForegroundColor Gray
Write-Host "  python examples\conversational_agent.py" -ForegroundColor Gray

