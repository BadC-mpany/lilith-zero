# scripts/start_agent.ps1
# Start the Sentinel conversational agent

Write-Host "=== Starting Sentinel Conversational Agent ===" -ForegroundColor Cyan

# 1. Bootstrap Utilities
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Parent $scriptPath
$envUtils = Join-Path $scriptDir "utils\env_utils.ps1"

if (-not (Test-Path $envUtils)) {
    Write-Error "Critical: env_utils.ps1 not found at $envUtils"
    exit 1
}

# Dot-source the utility script
. $envUtils

# 2. Setup Environment
$projectRoot = Get-ProjectRoot
Load-EnvFile -Path (Join-Path $projectRoot ".env")

$agentPath = Join-Path $projectRoot "sentinel_agent"
if (-not (Test-Path $agentPath)) {
    Write-Error "Agent directory not found: $agentPath"
    exit 1
}

# 3. Health Checks (Simplified)
function Test-Service {
    param([string]$Url, [string]$Name)
    try {
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec 3 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-Host "  [OK] $Name is running" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "  [FAIL] $Name is not responding ($Url)" -ForegroundColor Red
        return $false
    }
    return $false
}

Write-Host "`n[1] Verifying services..." -ForegroundColor Yellow
$interceptorOk = Test-Service -Url "http://localhost:8000/health" -Name "Interceptor"
$mcpOk = Test-Service -Url "http://localhost:9000/health" -Name "MCP Server"

if (-not $interceptorOk) {
    Write-Host "`n[ERROR] Interceptor is required. Run scripts\start_all.ps1 first." -ForegroundColor Red
    exit 1
}

# 4. Run Agent
Write-Host "`n[2] Starting Agent..." -ForegroundColor Yellow

$agentCommand = {
    $env:PYTHONPATH = $Global:agentPath
    Write-Host "--- Agent Session ---" -ForegroundColor Cyan
    python examples\conversational_agent.py
}

# Important: We need to pass the variable into the script block scope if using invoke-command logic
# But our Invoke-WithEnvironment runs in current scope roughly.
# Let's set PYTHONPATH in the wrapper to be safe.

# We'll use a new PowerShell process to allow interaction in clean window if double-clicked,
# but if running from terminal, we usually want to stay there.
# The previous script spawned a new window. Let's stick to that if user wants, 
# BUT generally running in the current terminal is better for DevEx unless explicitly "start separate".
# The user's script did `Start-Process powershell`.

# Let's verify how we want to run this. Robust dev scripts usually run in-line.
# If the user wants a separate window, they can `Start-Process`.
# I will make it run IN-LINE for better error visibility, OR provide a robust way to spawn.
# Given the user's previous "Agent window opened" output, they might expect a new window.
# However, for "agnostic" and "robust", inline is often better.
# Let's try running inline first. It's cleaner.

Invoke-WithEnvironment -ScriptBlock {
    # $agentPath is captured from parent scope
    Set-Location $agentPath
    $env:PYTHONPATH = $agentPath
    python examples\conversational_agent.py
}
