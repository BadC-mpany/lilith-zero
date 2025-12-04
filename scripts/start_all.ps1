# start_all.ps1
param(
    [switch]$SkipVerification
)

Write-Host "Starting Sentinel Services..." -ForegroundColor Cyan

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

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
        Write-Host "  [FAIL] PostgreSQL service not found" -ForegroundColor Red
    }
} catch {
    Write-Host "  [WARN] PostgreSQL may already be running or error: $_" -ForegroundColor Yellow
}

# Wait for services to initialize
Write-Host "`nWaiting 2 seconds for services to initialize..." -ForegroundColor Gray
Start-Sleep -Seconds 2

# Start Rust Interceptor (in new window)
Write-Host "`n[2] Starting Rust Interceptor..." -ForegroundColor Yellow
$rustPath = Join-Path $projectRoot "sentinel_core\interceptor\rust"
if (Test-Path $rustPath) {
    $rustCommand = "cd '$rustPath'; Write-Host '=== Rust Interceptor ===' -ForegroundColor Cyan; cargo run --bin sentinel-interceptor"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $rustCommand
    Write-Host "  [OK] Rust Interceptor window opened" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Rust interceptor path not found: $rustPath" -ForegroundColor Red
}

# Start MCP Server (in new window)
Write-Host "`n[3] Starting MCP Server..." -ForegroundColor Yellow
$mcpPath = Join-Path $projectRoot "sentinel_core\mcp"
if (Test-Path $mcpPath) {
    $mcpCommand = "cd '$mcpPath'; Write-Host '=== MCP Server ===' -ForegroundColor Cyan; python -m uvicorn src.mcp_server:app --host 0.0.0.0 --port 9000"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $mcpCommand
    Write-Host "  [OK] MCP Server window opened" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] MCP server path not found: $mcpPath" -ForegroundColor Red
}

Write-Host "`n=== Services Started ===" -ForegroundColor Green
Write-Host "Rust Interceptor: http://localhost:8000" -ForegroundColor Cyan
Write-Host "MCP Server: http://localhost:9000" -ForegroundColor Cyan
Write-Host "`nRun the agent in another terminal:" -ForegroundColor Yellow
Write-Host "  cd sentinel_agent; python examples\conversational_agent.py" -ForegroundColor Gray

if (-not $SkipVerification) {
    Write-Host "`nWaiting 5 seconds for services to initialize..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Write-Host "Running verification..." -ForegroundColor Yellow
    & "$scriptDir\verify_services.ps1"
}

