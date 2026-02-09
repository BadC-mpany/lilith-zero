param(
    [string]$UpstreamCmd = "python",
    [string]$UpstreamArgs = "tools.py",
    [string]$PolicyPath = "policy.yaml"
)

$env:LILITH_ZERO_POLICY_PATH = $PolicyPath

if (-not (Test-Path "$PSScriptRoot/../lilith-zero/target/release/lilith-zero.exe")) {
    Write-Warning "Binary not found. Building..."
    & "$PSScriptRoot/build.ps1"
}

& "$PSScriptRoot/../lilith-zero/target/release/lilith-zero.exe" `
    --upstream-cmd $UpstreamCmd -- $UpstreamArgs.Split(" ")
