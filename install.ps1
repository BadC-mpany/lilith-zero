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

$DownloadUrl = "https://github.com/BadC-mpany/lilith-zero/releases/download/$Version/lilith-zero-windows-x86_64.exe"
$ChecksumUrl = "https://github.com/BadC-mpany/lilith-zero/releases/download/$Version/checksums.sha256"
$DestPath = Join-Path $INSTALL_DIR $BINARY_NAME
$TempChecksum = Join-Path $env:TEMP "checksums.sha256"

# --- Create Directory ---
if (-not (Test-Path $INSTALL_DIR)) {
    New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
}

Write-Host "Downloading $Version -> $DestPath..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $DownloadUrl -OutFile $DestPath
Invoke-WebRequest -Uri $ChecksumUrl -OutFile $TempChecksum

# --- Verify Checksum ---
Write-Host "Verifying checksum..." -ForegroundColor Cyan
$ExpectedHashLine = Select-String -Path $TempChecksum -Pattern "lilith-zero-windows-x86_64.exe"
if ($null -eq $ExpectedHashLine) {
    Write-Error "Checksum for Windows binary not found in checksums.sha256"
    exit 1
}
$ExpectedHash = $ExpectedHashLine.ToString().Split(" ")[0].ToUpper()
$ActualHash = (Get-FileHash -Path $DestPath -Algorithm SHA256).Hash.ToUpper()

if ($ExpectedHash -ne $ActualHash) {
    Write-Error "SECURITY ERROR: SHA-256 checksum mismatch!`nExpected: $ExpectedHash`nActual:   $ActualHash"
    Remove-Item $DestPath
    exit 1
}
Write-Host "Checksum OK." -ForegroundColor Green
Remove-Item $TempChecksum

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
