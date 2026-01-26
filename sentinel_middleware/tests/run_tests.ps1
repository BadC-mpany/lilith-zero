param(
    [ValidateSet("Unit", "Integration", "All")]
    [string]$Type = "All"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir/.."

Push-Location $ProjectRoot

function Run-CargoTest {
    param([string[]]$CliArgs)
    Write-Host "Running: cargo test $CliArgs" -ForegroundColor Cyan
    & cargo test @CliArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Tests failed!"
    }
}

try {
    if ($Type -eq "Unit" -or $Type -eq "All") {
        Write-Host "`n=== Running UNIT Tests ===" -ForegroundColor Green
        # 1. Run inline unit tests in src/
        Write-Host "--- src/ unit tests ---" -ForegroundColor Gray
        Run-CargoTest "--lib"

        # 2. Run tests in tests/unit/ (exposed as 'unit' integration test target)
        if (Test-Path "tests/unit/mod.rs") {
            Write-Host "--- tests/unit/ suite ---" -ForegroundColor Gray
            Run-CargoTest "--test", "unit"
        } else {
            Write-Warning "tests/unit/mod.rs not found. 'tests/unit' directory tests may not be running."
        }
    }

    if ($Type -eq "Integration" -or $Type -eq "All") {
        Write-Host "`n=== Running INTEGRATION Tests ===" -ForegroundColor Green
        # 3. Run tests in tests/integration/ (exposed as 'integration' target)
        if (Test-Path "tests/integration/mod.rs") {
            Run-CargoTest "--test", "integration"
        } else {
            Write-Warning "tests/integration/mod.rs not found."
        }
    }
}
finally {
    Pop-Location
}
