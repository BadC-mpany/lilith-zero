# start_agent.ps1
# Start the Sentinel conversational agent

Write-Host "=== Starting Sentinel Conversational Agent ===" -ForegroundColor Cyan

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$agentPath = Join-Path $projectRoot "sentinel_agent"

# Check if agent path exists
if (-not (Test-Path $agentPath)) {
    Write-Host "[FAIL] Agent path not found: $agentPath" -ForegroundColor Red
    exit 1
}

# Check if .env file exists and load it
$envFile = Join-Path $projectRoot ".env"
if (Test-Path $envFile) {
    Write-Host "  [OK] .env file found" -ForegroundColor Green
    # Load .env file for the agent process
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim().Trim('"').Trim("'")
            [Environment]::SetEnvironmentVariable($key, $value, "Process")
        }
    }
} else {
    Write-Host "  [WARN] .env file not found at: $envFile" -ForegroundColor Yellow
    Write-Host "    Agent may not work without proper configuration" -ForegroundColor Yellow
}

# Check for required environment variables
if (-not $env:OPENROUTER_API_KEY) {
    Write-Host "`n[WARN] OPENROUTER_API_KEY not set" -ForegroundColor Yellow
    Write-Host "  The agent requires OPENROUTER_API_KEY to function" -ForegroundColor Yellow
    Write-Host "  Set it in .env file or environment" -ForegroundColor Gray
}

# Verify services are running before starting agent
Write-Host "`n[1] Verifying services are running..." -ForegroundColor Yellow
$servicesReady = $true

# Check Rust Interceptor
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 5 -ErrorAction Stop
    if ($response.StatusCode -eq 200) {
        Write-Host "  [OK] Rust Interceptor is running" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Rust Interceptor returned status $($response.StatusCode)" -ForegroundColor Red
        $servicesReady = $false
    }
} catch {
    Write-Host "  [FAIL] Rust Interceptor not responding" -ForegroundColor Red
    Write-Host "    Error: $_" -ForegroundColor Gray
    Write-Host "    Start services first: .\scripts\start_all.ps1" -ForegroundColor Yellow
    $servicesReady = $false
}

# Check MCP Server (use /health endpoint)
try {
    $response = Invoke-WebRequest -Uri "http://localhost:9000/health" -TimeoutSec 5 -ErrorAction Stop
    if ($response.StatusCode -eq 200) {
        Write-Host "  [OK] MCP Server is running" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] MCP Server returned status $($response.StatusCode)" -ForegroundColor Red
        $servicesReady = $false
    }
} catch {
    Write-Host "  [FAIL] MCP Server not responding" -ForegroundColor Red
    Write-Host "    Error: $_" -ForegroundColor Gray
    Write-Host "    Start services first: .\scripts\start_all.ps1" -ForegroundColor Yellow
    $servicesReady = $false
}

if (-not $servicesReady) {
    Write-Host "`n[ERROR] Services are not running. Please start them first:" -ForegroundColor Red
    Write-Host "  .\scripts\start_all.ps1" -ForegroundColor Yellow
    exit 1
}

# Start the agent
Write-Host "`n[2] Starting Conversational Agent..." -ForegroundColor Yellow

# Build command - Python dotenv will load .env automatically from project root
$agentCommand = "cd '$agentPath'; Write-Host '=== Sentinel Conversational Agent ===' -ForegroundColor Cyan; Write-Host 'Loading configuration...' -ForegroundColor Gray; python examples\conversational_agent.py"

Start-Process powershell -ArgumentList "-NoExit", "-Command", $agentCommand

Write-Host "  [OK] Agent window opened" -ForegroundColor Green
Write-Host "`n=== Agent Started ===" -ForegroundColor Green
Write-Host "The agent is now running in a separate window." -ForegroundColor Cyan
Write-Host "You can interact with it in that window." -ForegroundColor Cyan

