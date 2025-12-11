# Run the Sentinel Conversational Agent
# This script sets up the environment (venv + .env), installs local packages if needed, and runs the agent.

$ErrorActionPreference = "Stop"

$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Parent $scriptPath
$projectRoot = Split-Path -Parent $scriptDir

# 1. Import Utils & Load Environment
$envUtils = Join-Path $projectRoot "scripts\utils\env_utils.ps1"
if (-not (Test-Path $envUtils)) {
    Write-Error "env_utils.ps1 not found at $envUtils"
    exit 1
}
. $envUtils

Write-Host "=== Sentinel Agent Launcher ===" -ForegroundColor Cyan

# Load .env
$envFile = Join-Path $projectRoot ".env"
if (Test-Path $envFile) {
    Load-EnvFile -Path $envFile
} else {
    Write-Warning ".env file not found at $envFile. Relying on existing environment variables."
}

# 2. Run in Python Environment
Invoke-WithEnvironment -ScriptBlock {
    # 2a. Check/Install Local Packages
    Write-Host "Checking local package installation..." -ForegroundColor Gray
    
    $sdkDir = Join-Path $projectRoot "sentinel_sdk"
    $agentDir = Join-Path $projectRoot "sentinel_agent"

    # Check SDK
    python -c "import sentinel_sdk" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installing sentinel_sdk (editable)..." -ForegroundColor Yellow
        pip install -e $sdkDir
    }

    # Check Agent
    python -c "import sentinel_agent" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installing sentinel_agent (editable)..." -ForegroundColor Yellow
        pip install -e $agentDir
    }
    
    # 2b. Check API Keys
    if (-not $env:SENTINEL_API_KEY) {
        Write-Error "SENTINEL_API_KEY is not set. Please add it to .env or set it in your shell."
        exit 1
    }
    
    if (-not $env:OPENROUTER_API_KEY) {
        Write-Warning "OPENROUTER_API_KEY is not set. LLM capabilities may fail."
    }

    # 3. Run Agent
    $AgentScript = "$agentDir\examples\conversational_agent.py"
    
    Write-Host "Starting Agent..." -ForegroundColor Green
    Write-Host "  Script: $AgentScript"
    Write-Host "  URL: $($env:SENTINEL_URL -replace '/$','')"
    
    python $AgentScript -v
}
