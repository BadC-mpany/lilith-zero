# scripts/backend/run_interceptor_wrapper.ps1
# Wrapper to run Rust Interceptor

$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Parent $scriptPath
$projectRoot = Split-Path -Parent (Split-Path -Parent $scriptDir)

Write-Host "=== Rust Interceptor ===" -ForegroundColor Cyan
Write-Host "Initializing..." -ForegroundColor Gray

$interceptorDir = Join-Path $projectRoot "sentinel_core\interceptor\rust"
if (-not (Test-Path $interceptorDir)) {
    Write-Error "Interceptor directory not found at $interceptorDir"
    Read-Host "Press Enter to exit..."
    exit 1
}

# Load environment variables
$utilsDir = Join-Path $projectRoot "scripts\utils"
if (Test-Path "$utilsDir\env_utils.ps1") {
    . "$utilsDir\env_utils.ps1"
    Load-EnvFile "$projectRoot\.env"
    Write-Host "Loaded environment variables from .env" -ForegroundColor Gray
} else {
    Write-Warning "env_utils.ps1 not found, assuming env vars are set."
}

Set-Location $interceptorDir

Write-Host "Compiling and starting..." -ForegroundColor Yellow
cargo run --bin sentinel-interceptor 2>&1 | Tee-Object -FilePath "interceptor.log"

if ($LASTEXITCODE -ne 0) {
    Write-Host "`nInterceptor exited with error code $LASTEXITCODE" -ForegroundColor Red
    Read-Host "Press Enter to exit..."
}
