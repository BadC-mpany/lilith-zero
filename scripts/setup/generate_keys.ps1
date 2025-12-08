# scripts/setup/generate_keys.ps1
# Generate Ed25519 key pair using Python (Crypto-agnostic)

$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Parent $scriptPath
$projectRoot = Split-Path -Parent (Split-Path -Parent $scriptDir)

# Import Env Utils
$envUtils = Join-Path $projectRoot "scripts\utils\env_utils.ps1"
if (Test-Path $envUtils) {
    . $envUtils
} else {
    Write-Error "env_utils.ps1 not found"
    exit 1
}

Write-Host "=== Generating Keys ===" -ForegroundColor Cyan

# Use Python wrapper
$pyScript = Join-Path $scriptDir "generate_keys.py"
$secretsDir = Join-Path $projectRoot "sentinel_core\secrets"

Invoke-WithEnvironment -ScriptBlock {
    param($Script, $Output)
    python $Script $Output
} -ArgumentList $pyScript, $secretsDir

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nKeys ready." -ForegroundColor Green
} else {
    Write-Host "`nKey generation failed." -ForegroundColor Red
}
