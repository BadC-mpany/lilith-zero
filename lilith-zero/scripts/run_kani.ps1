# Kani verification via Docker
# Single compilation pass - runs ALL proof harnesses at once
$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "=== Building Kani Docker image ===" -ForegroundColor Cyan
docker build -t lilith-kani -f kani.Dockerfile . 2>$null | Select-Object -Last 1

Write-Host ""
Write-Host "=== Running ALL Kani proof harnesses (single compilation) ===" -ForegroundColor Cyan
Write-Host "Compiling + verifying... takes ~60s on first run" -ForegroundColor DarkGray
Write-Host ""

# Run cargo kani (no --harness = run ALL harnesses in one pass)
$rawOutput = docker run --rm -v "${PWD}:/app" lilith-kani cargo kani 2>$null
$exitCode = $LASTEXITCODE

# Build output array
$output = @()
if ($rawOutput) {
    $output = $rawOutput | ForEach-Object { "$_" }
}

# Extract verification results
$verification_lines = $output | Where-Object { $_ -match "^VERIFICATION:" }
$total_success = @($verification_lines | Where-Object { $_ -match "SUCCESSFUL" }).Count
$total_fail = @($verification_lines | Where-Object { $_ -match "FAILED" }).Count
$total = $total_success + $total_fail

# Print clean report
Write-Host ""
Write-Host "========================================================" -ForegroundColor Yellow
Write-Host "              KANI VERIFICATION REPORT                  " -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Yellow
Write-Host ""

$currentHarness = ""
foreach ($line in $output) {
    if ($line -match "Checking harness (.+)\.\.\.") {
        $currentHarness = $Matches[1] -replace "verification::verification::", ""
    }
    if ($line -match "Status: SUCCESS") {
        Write-Host "  [PASS] $currentHarness" -ForegroundColor Green
    }
    if ($line -match "Status: FAILURE") {
        Write-Host "  [FAIL] $currentHarness" -ForegroundColor Red
    }
}

# Harness summary from Kani
$harness_summary = $output | Where-Object { $_ -match "^Complete" -or $_ -match "^Manual Harness" }
Write-Host ""
Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
foreach ($line in $harness_summary) {
    Write-Host "  $line" -ForegroundColor Cyan
}
Write-Host "--------------------------------------------------------" -ForegroundColor Yellow
Write-Host ""

if ($total_fail -eq 0 -and $total_success -gt 0) {
    Write-Host "  All $total_success proofs verified successfully." -ForegroundColor Green
    exit 0
} elseif ($total -eq 0) {
    Write-Host "  WARNING: No harness results found." -ForegroundColor Yellow
    Write-Host "  Last 15 lines of Kani output:" -ForegroundColor DarkGray
    $output | Select-Object -Last 15 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    exit 1
} else {
    Write-Host "  $total_fail of $total proofs FAILED." -ForegroundColor Red
    $output | Where-Object { $_ -match "FAILED|error\[" } | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}
