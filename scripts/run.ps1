param(
    [string]$UpstreamCmd = "python",
    [string]$UpstreamArgs = "tools.py",
    [string]$PolicyPath = "policy.yaml"
)

$env:POLICIES_YAML_PATH = $PolicyPath

if (-not (Test-Path "$PSScriptRoot/../sentinel_middleware/target/release/sentinel-interceptor.exe")) {
    Write-Warning "Binary not found. Building..."
    & "$PSScriptRoot/build.ps1"
}

& "$PSScriptRoot/../sentinel_middleware/target/release/sentinel-interceptor.exe" `
    --upstream-cmd $UpstreamCmd -- $UpstreamArgs.Split(" ")
