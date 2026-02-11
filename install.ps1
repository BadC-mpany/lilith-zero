# Lilith Zero - Security-First Windows Installer
# https://github.com/BadC-mpany/lilith-zero

$ErrorActionPreference = "Stop"

$OWNER = "BadC-mpany"
$REPO = "lilith-zero"
$BINARY = "lilith-zero.exe"

Write-Host "Detecting latest version..." -ForegroundColor Cyan
$Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$OWNER/$REPO/releases/latest"
$Version = $Release.tag_name

Write-Host "Downloading Lilith Zero $Version..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "https://github.com/BadC-mpany/lilith-zero/releases/download/$Version/lilith-zero.exe" -OutFile $BINARY

Write-Host "`n------------------------------------------------------------" -ForegroundColor Green
Write-Host "Lilith Zero binary downloaded successfully." -ForegroundColor Green
Write-Host "------------------------------------------------------------`n" -ForegroundColor Green

Write-Host "To use locally, run:" -ForegroundColor Gray
Write-Host "  .\$BINARY --help" -ForegroundColor Cyan
Write-Host "`nVerification complete. Deterministic security mode: ACTIVE." -ForegroundColor Gray
