# Generate SHA-256 hash of API key
param(
    [string]$ApiKey = "sk_live_demo_123"
)

$sha256 = [System.Security.Cryptography.SHA256]::Create()
$bytes = [System.Text.Encoding]::UTF8.GetBytes($ApiKey)
$hashBytes = $sha256.ComputeHash($bytes)
$hashString = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""

Write-Host "API Key: $ApiKey" -ForegroundColor Cyan
Write-Host "SHA-256 Hash: $hashString" -ForegroundColor Green
Write-Host ""
Write-Host "Use this hash in database setup script" -ForegroundColor Yellow

# Save to file for use in database script
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$hashFile = Join-Path $scriptDir "api_key_hash.txt"
$hashString | Out-File -FilePath $hashFile -NoNewline -Encoding UTF8

Write-Host "Hash saved to: $hashFile" -ForegroundColor Gray

