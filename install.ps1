# Lilith Zero - Enterprise Installer (Windows)
# https://github.com/BadC-mpany/lilith-zero

$ErrorActionPreference = "Stop"

$OWNER = "BadC-mpany"
$REPO = "lilith-zero"
$BINARY_NAME = "lilith-zero.exe"
$INSTALL_DIR = "$env:LOCALAPPDATA\Programs\lilith-zero\bin"

Write-Host "Lilith Zero | Initializing..." -ForegroundColor Cyan

# --- Fetch Latest ---
try {
    $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$OWNER/$REPO/releases/latest"
    $Version = $Release.tag_name
} catch {
    Write-Error "Failed to check latest version. Is GitHub API down?"
    exit 1
}

$DownloadUrl = "https://github.com/BadC-mpany/lilith-zero/releases/download/$Version/lilith-zero.exe"
$DestPath = Join-Path $INSTALL_DIR $BINARY_NAME

# --- Create Directory ---
if (-not (Test-Path $INSTALL_DIR)) {
    New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
}

Write-Host "Downloading $Version -> $DestPath..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $DownloadUrl -OutFile $DestPath

# --- PATH Management ---
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$INSTALL_DIR*") {
    Write-Host "Updating User PATH Environment Variable..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$INSTALL_DIR", "User")
    $env:Path += ";$INSTALL_DIR"
    Write-Host "Added $INSTALL_DIR to PATH." -ForegroundColor Green
}

Write-Host "`n------------------------------------------------------------" -ForegroundColor Green
Write-Host "  INSTALLED: $DestPath" -ForegroundColor Green
Write-Host "------------------------------------------------------------`n" -ForegroundColor Green

& $DestPath --version
Write-Host "Environment configured. Restart your terminal to refresh PATH if needed." -ForegroundColor Gray
