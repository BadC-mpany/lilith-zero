# Generate Ed25519 key pair for JWT signing
# This script uses OpenSSL if available, otherwise provides instructions

param(
    [string]$OutputDir = "sentinel_core/interceptor/rust/keys"
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$keysDir = Join-Path $projectRoot $OutputDir

Write-Host "Generating Ed25519 key pair..." -ForegroundColor Cyan

# Create keys directory
New-Item -ItemType Directory -Force -Path $keysDir | Out-Null

# Check for OpenSSL
$opensslPath = Get-Command openssl -ErrorAction SilentlyContinue

if ($opensslPath) {
    Write-Host "Using OpenSSL to generate keys..." -ForegroundColor Green
    
    $privateKeyPath = Join-Path $keysDir "interceptor_private_key.pem"
    $publicKeyPath = Join-Path $keysDir "interceptor_public_key.pem"
    
    # Generate private key
    openssl genpkey -algorithm Ed25519 -out $privateKeyPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error generating private key" -ForegroundColor Red
        exit 1
    }
    
    # Generate public key from private key
    openssl pkey -in $privateKeyPath -pubout -out $publicKeyPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error generating public key" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Keys generated successfully!" -ForegroundColor Green
    Write-Host "Private key: $privateKeyPath" -ForegroundColor Gray
    Write-Host "Public key: $publicKeyPath" -ForegroundColor Gray
} else {
    Write-Host "OpenSSL not found in PATH" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Option 1: Install OpenSSL for Windows:" -ForegroundColor Cyan
    Write-Host "  Download from: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Gray
    Write-Host "  Add to PATH: C:\Program Files\OpenSSL-Win64\bin" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Option 2: Use online tool or generate keys manually:" -ForegroundColor Cyan
    Write-Host "  Private key should be saved to: $privateKeyPath" -ForegroundColor Gray
    Write-Host "  Public key should be saved to: $publicKeyPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To generate keys manually with OpenSSL:" -ForegroundColor Yellow
    Write-Host "  cd $keysDir" -ForegroundColor Gray
    Write-Host "  openssl genpkey -algorithm Ed25519 -out interceptor_private_key.pem" -ForegroundColor Gray
    Write-Host "  openssl pkey -in interceptor_private_key.pem -pubout -out interceptor_public_key.pem" -ForegroundColor Gray
    exit 1
}

