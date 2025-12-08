# Copy public key to MCP server directory for token verification
param(
    [string]$ProjectRoot = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
)

$privateKeyPath = Join-Path $ProjectRoot "sentinel_core\interceptor\rust\keys\interceptor_private_key.pem"
$publicKeyPath = Join-Path $ProjectRoot "sentinel_core\interceptor\rust\keys\interceptor_public_key.pem"
$mcpKeysDir = Join-Path $ProjectRoot "sentinel_core\mcp\keys"
$mcpPublicKeyPath = Join-Path $mcpKeysDir "interceptor_public_key.pem"

Write-Host "Copying public key to MCP server..." -ForegroundColor Cyan

# Check if public key exists
if (-not (Test-Path $publicKeyPath)) {
    Write-Host "Error: Public key not found at $publicKeyPath" -ForegroundColor Red
    Write-Host "Run scripts/generate_keys.ps1 first to generate keys" -ForegroundColor Yellow
    exit 1
}

# Create MCP keys directory if it doesn't exist
if (-not (Test-Path $mcpKeysDir)) {
    New-Item -ItemType Directory -Force -Path $mcpKeysDir | Out-Null
    Write-Host "Created directory: $mcpKeysDir" -ForegroundColor Gray
}

# Copy public key
Copy-Item -Path $publicKeyPath -Destination $mcpPublicKeyPath -Force
Write-Host "Public key copied successfully!" -ForegroundColor Green
Write-Host "Source: $publicKeyPath" -ForegroundColor Gray
Write-Host "Destination: $mcpPublicKeyPath" -ForegroundColor Gray

