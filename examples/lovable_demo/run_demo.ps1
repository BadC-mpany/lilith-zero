# Lilith Zero - Lovable AI Security Demo Setup & Launcher
# Optimized for Windows and macOS (via PowerShell Core)

$ErrorActionPreference = "Stop"

Write-Host "`n------------------------------------------------------------" -ForegroundColor Cyan
Write-Host " LILITH ZERO - MCP SECURITY MIDDLEWARE SETUP " -ForegroundColor Cyan
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

# 1. Environment Detection (Project Root)
$ScriptDir = $PSScriptRoot
$RootDir = [System.IO.Path]::GetFullPath((Join-Path $ScriptDir "../../"))

$IsWin = if ($null -ne $IsWindows) { $IsWindows } else { $env:OS -like "*Windows*" }
$BinaryName = if ($IsWin) { "lilith-zero.exe" } else { "lilith-zero" }
$BinaryPath = Join-Path $RootDir "lilith-zero/target/release/$BinaryName"
$VenvDir = Join-Path $RootDir ".venv"
$PythonExec = if ($IsWin) { Join-Path $VenvDir "Scripts/python.exe" } else { Join-Path $VenvDir "bin/python" }

# 2. Check Prerequisites
function Check-Command($cmd) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        Write-Host "[OK] $cmd is installed." -ForegroundColor Green
        return $true
    } else {
        Write-Host "[ERROR] $cmd is missing. Please install it to continue." -ForegroundColor Red
        return $false
    }
}

if (-not (Check-Command "cargo") -or -not (Check-Command "python")) {
    Write-Host "`nMissing requirements. Please install Rust (cargo) and Python." -ForegroundColor Yellow
    exit 1
}

$HasUv = Check-Command "uv"

# 3. Build Middleware (Rust)
Write-Host "`n[STEP 1/3] Building Lilith Zero Middleware (Rust)..." -ForegroundColor Cyan
Push-Location (Join-Path $RootDir "lilith-zero")
try {
    cargo build --release
    Write-Host "Middleware build successful." -ForegroundColor Green
} finally {
    Pop-Location
}

# 4. Setup Python Environment
Write-Host "`n[STEP 2/3] Preparing Python Sandbox Environment..." -ForegroundColor Cyan
if (-not (Test-Path $VenvDir)) {
    Write-Host "Creating virtual environment..."
    if ($HasUv) {
        & uv venv "$VenvDir"
    } else {
        & python -m venv "$VenvDir"
    }
}

# Set environment variables for the current process to force isolation
$env:VIRTUAL_ENV = $VenvDir
$env:UV_PYTHON = $PythonExec

Write-Host "Installing/Updating dependencies..."
Push-Location $RootDir
try {
    if ($HasUv) {
        # Using --python and --no-system to ensure absolute isolation
        & uv pip install --python "$PythonExec" --no-system -r requirements.txt
    } else {
        & $PythonExec -m pip install -r requirements.txt
    }
} finally {
    Pop-Location
}

# 5. Run Demo
Write-Host "`n[STEP 3/3] Launching Security Demo..." -ForegroundColor Cyan
Write-Host "Starting interactive session...`n" -ForegroundColor Gray

# Ensure we use the correct Python from venv to run the demo
& $PythonExec (Join-Path $ScriptDir "secure_vibe_demo.py")
