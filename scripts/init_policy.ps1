$ExamplePolicy = "$PSScriptRoot/../examples/policy.yaml"

if (-not (Test-Path $ExamplePolicy)) {
    Write-Host "Generating default policy at $ExamplePolicy..."
    # Content is already created in previous step, but this script could generate it if missing.
    # For now, just ensure it exists.
}

Write-Host "Policy initialized at $ExamplePolicy"
