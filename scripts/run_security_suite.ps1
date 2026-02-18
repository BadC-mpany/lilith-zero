#!/usr/bin/env pwsh
# Centralized Security Verification Script for Lilith Zero
# Usage: ./run_security_suite.ps1
#
# This script orchestrates the entire security engineering sweep:
# 1. Rust Static Analysis (Clippy, Audit)
# 2. Rust Core Tests
# 3. Python SDK Tests & Red Team Attacks
# 4. Formal Verification (Kani) - Native on Linux, Docker on Windows
# 5. Fuzzing (Smoke Test - Linux Only)

$ErrorActionPreference = "Stop"

function Print-Header ($msg) {
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host " $msg" -ForegroundColor Cyan
    Write-Host "========================================================`n" -ForegroundColor Cyan
}

function Run-Command ($Command, $Arguments) {
    Write-Host "[EXEC] $Command $Arguments" -ForegroundColor Gray
    & $Command $Arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error executing command: $Command" -ForegroundColor Red
        exit 1
    }
}

# --------------------------------------------------------------------------
# 1. Rust Static Analysis
# --------------------------------------------------------------------------
Print-Header "PHASE 1: Rust Static Analysis"
Set-Location "$PSScriptRoot/../lilith-zero"

Write-Host "Running Cargo Fmt (Strict)..." -ForegroundColor Yellow
Run-Command "cargo" "fmt", "--all", "--", "--check"

Write-Host "Running Cargo Clippy..." -ForegroundColor Yellow
Run-Command "cargo" "clippy", "--all-targets", "--all-features", "--", "-D", "warnings"

# Check for cargo-audit (Optional but recommended)
if (Get-Command "cargo-audit" -ErrorAction SilentlyContinue) {
    Write-Host "Running Cargo Audit..." -ForegroundColor Yellow
    Run-Command "cargo" "audit"
} else {
    Write-Host "Skipping cargo audit (not installed)" -ForegroundColor DarkGray
}

# --------------------------------------------------------------------------
# 2. Rust Core Tests
# --------------------------------------------------------------------------
Print-Header "PHASE 2: Rust Core Tests"
Write-Host "Running Cargo Test..." -ForegroundColor Yellow
Run-Command "cargo" "test", "--all-features"

# --------------------------------------------------------------------------
# 3. Python SDK & Red Team
# --------------------------------------------------------------------------
Print-Header "PHASE 3: Python SDK & Red Team"
Set-Location "$PSScriptRoot/../sdk"

# Check for uv
if (Get-Command "uv" -ErrorAction SilentlyContinue) {
    # Ensure virtual environment exists
    if (-not (Test-Path ".venv")) {
        Write-Host "Creating virtual environment (.venv)..." -ForegroundColor Yellow
        Run-Command "uv" "venv"
    }
    
    $venvPath = ".venv"

    Write-Host "Installing SDK dependencies..." -ForegroundColor Yellow
    # Explicitly target the local venv to prevent system-wide install attempts
    Run-Command "uv" "pip", "install", "--python", $venvPath, "-e", "."
    Run-Command "uv" "pip", "install", "--python", $venvPath, "pytest", "pytest-asyncio", "pyjwt", "faker"
    
    Write-Host "Running Pytest (Unit + Red Team)..." -ForegroundColor Yellow
    # uv run automatically detects the local .venv
    Run-Command "uv" "run", "pytest"
} else {
    Write-Host "uv not found, skipping Python tests (Ensure uv is installed)" -ForegroundColor Red
}

# --------------------------------------------------------------------------
# 4. Formal Verification (Kani)
# --------------------------------------------------------------------------
Print-Header "PHASE 4: Formal Verification (Kani)"
Set-Location "$PSScriptRoot/../lilith-zero"

if ($IsLinux) {
    # On Linux (CI), run natively
    if (Get-Command "cargo-kani" -ErrorAction SilentlyContinue) {
        Write-Host "Running Kani (Native Linux)..." -ForegroundColor Yellow
        Run-Command "cargo" "kani"
    } else {
        Write-Host "cargo-kani not found! Please install 'kani-verifier'." -ForegroundColor Red
        # Don't fail the whole suite if kani isn't installed locally, unless in CI
        if ($env:CI) { exit 1 }
    }
} else {
    # On Windows, use the Docker shim
    if (Test-Path "run_kani.ps1") {
        Write-Host "Running Kani (Docker wrapper)..." -ForegroundColor Yellow
        # Call the existing script
        & ./run_kani.ps1
        if ($LASTEXITCODE -ne 0) { exit 1 }
    } else {
        Write-Host "run_kani.ps1 not found!" -ForegroundColor Red
    }
}

# --------------------------------------------------------------------------
# 5. Miri (Undefined Behavior)
# --------------------------------------------------------------------------
Print-Header "PHASE 5: Miri (Undefined Behavior)"
Set-Location "$PSScriptRoot/../lilith-zero"

# Try to run miri if available, or install nightly if needed
try {
    if (Get-Command "cargo-miri" -ErrorAction SilentlyContinue) {
        Write-Host "Running Miri..." -ForegroundColor Yellow
        Run-Command "cargo" "miri", "test"
    } else {
        Write-Host "cargo-miri not found. Attempting install via rustup..." -ForegroundColor DarkGray
        # This might fail if rustup is not in path or network issues, hence try/catch
        Run-Command "rustup" "toolchain", "install", "nightly", "--component", "miri"
        Run-Command "cargo" "+nightly", "miri", "test"
    }
} catch {
    Write-Host "Miri execution failed or not available. Skipping." -ForegroundColor Red
    if ($env:CI) { exit 1 }
}

Print-Header "SECURITY SUITE COMPLETED SUCCESSFULLY"
exit 0
