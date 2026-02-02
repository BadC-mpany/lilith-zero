$env:OPENROUTER_API_KEY = Read-Host "Please enter your OpenRouter API Key"
$env:SENTINEL_LOG_LEVEL = "info" 

Write-Host "`n=== Sentinel ReAct Demo ===" -ForegroundColor Cyan
Write-Host "Starting Agent...`n"

# Run agent.py in the same directory as the script
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
pushd $scriptDir
python agent.py
popd
