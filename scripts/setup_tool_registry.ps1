# Setup tool registry YAML file for Rust interceptor
param(
    [string]$ProjectRoot = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
)

$sourceRegistry = Join-Path $ProjectRoot "rule_maker\data\tool_registry.yaml"
$targetDir = Join-Path $ProjectRoot "sentinel_core\interceptor\rust\config"
$targetRegistry = Join-Path $targetDir "tool_registry.yaml"

Write-Host "Setting up tool registry..." -ForegroundColor Cyan

# Check if source exists
if (-not (Test-Path $sourceRegistry)) {
    Write-Host "Error: Source tool registry not found at $sourceRegistry" -ForegroundColor Red
    exit 1
}

# Create target directory if it doesn't exist
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    Write-Host "Created directory: $targetDir" -ForegroundColor Gray
}

# Copy tool registry
Copy-Item -Path $sourceRegistry -Destination $targetRegistry -Force
Write-Host "Tool registry copied successfully!" -ForegroundColor Green
Write-Host "Source: $sourceRegistry" -ForegroundColor Gray
Write-Host "Destination: $targetRegistry" -ForegroundColor Gray
Write-Host ""
Write-Host "Update your .env file with:" -ForegroundColor Yellow
Write-Host "  TOOL_REGISTRY_YAML_PATH=./config/tool_registry.yaml" -ForegroundColor Gray

