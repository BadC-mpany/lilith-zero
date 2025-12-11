# Run the Sentinel Conversational Agent
# This script sets up the environment and runs the agent.

# 1. Configuration - Set these or use existing env vars
$env:SENTINEL_URL = "http://localhost:8000"
# $env:SENTINEL_API_KEY = "..." # user should set this or we prompt?
# $env:OPENROUTER_API_KEY = "..." 

# Check for API Keys
if (-not $env:SENTINEL_API_KEY) {
    Write-Host "Error: SENTINEL_API_KEY environment variable is not set." -ForegroundColor Red
    Write-Host "Please set it: `$env:SENTINEL_API_KEY = 'your_key'"
    exit 1
}

if (-not $env:OPENROUTER_API_KEY) {
    Write-Host "Warning: OPENROUTER_API_KEY is not set. The agent might fail if LLM requires it." -ForegroundColor Yellow
}

# 2. Check dependencies
# Assuming virtual env is active or packages installed
# python -c "import sentinel_sdk"

# 3. access the example agent
# path relative to script
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path
$ProjectRoot = (Get-Item $ScriptDir).Parent.FullName
$AgentScript = "$ProjectRoot\sentinel_agent\examples\conversational_agent.py"

Write-Host "Starting Sentinel Agent..." -ForegroundColor Green
Write-Host "Sentinel URL: $env:SENTINEL_URL"
Write-Host "Agent Script: $AgentScript"

# Add src to pythonpath so it can find sentinel_agent package if not installed editable
$env:PYTHONPATH = "$ProjectRoot;$ProjectRoot\sentinel_sdk\src;$env:PYTHONPATH"

# Run
python $AgentScript -v
