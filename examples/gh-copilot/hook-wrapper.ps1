# Lilith Zero — gh copilot CLI hook wrapper (Windows PowerShell)
#
# This script is invoked by gh copilot for every tool call on Windows.
# It finds the lilith-zero binary and forwards stdin to the policy engine.
#
# Required env vars (set via hooks.json "env" field or export):
#   LILITH_ZERO_BIN      Absolute path to the lilith-zero binary.
#                        Falls back to 'lilith-zero.exe' on PATH.
#   LILITH_ZERO_EVENT    The hook event name: preToolUse, postToolUse, etc.
#                        Must be set via the hooks.json env block.
#   LILITH_ZERO_POLICY   Path to the policy YAML file. Optional — auto-discovered.
#
# Output format for gh copilot CLI: {"permissionDecision": "allow"/"deny"}
#
# WINDOWS NOTES
#   Run once: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Fail-closed: emit Copilot deny and exit 0
# ---------------------------------------------------------------------------
function Deny-Request {
    param([string]$Reason = 'internal error')
    $escaped = $Reason -replace '\\', '\\\\' -replace '"', '\"'
    Write-Output "{`"permissionDecision`":`"deny`",`"permissionDecisionReason`":`"$escaped`"}"
    exit 0
}

# ---------------------------------------------------------------------------
# Locate binary
# ---------------------------------------------------------------------------
$LilithBin = $env:LILITH_ZERO_BIN

if (-not $LilithBin) {
    $found = Get-Command 'lilith-zero.exe' -ErrorAction SilentlyContinue
    if ($found) { $LilithBin = $found.Source }
}

if (-not $LilithBin) {
    Deny-Request 'lilith-zero binary not found: set LILITH_ZERO_BIN or add it to PATH'
}

if (-not [System.IO.Path]::IsPathRooted($LilithBin)) {
    Deny-Request "LILITH_ZERO_BIN must be an absolute path, got: $LilithBin"
}

if (-not (Test-Path -LiteralPath $LilithBin -PathType Leaf)) {
    Deny-Request "lilith-zero binary not found at: $LilithBin"
}

# ---------------------------------------------------------------------------
# Validate event name
# ---------------------------------------------------------------------------
$Event = $env:LILITH_ZERO_EVENT
if (-not $Event) {
    Deny-Request 'LILITH_ZERO_EVENT not set — add it to the hooks.json env block'
}

$ValidEvents = @('preToolUse','postToolUse','sessionStart','sessionEnd','userPromptSubmitted','errorOccurred')
if ($Event -notin $ValidEvents) {
    Deny-Request "Invalid LILITH_ZERO_EVENT: $Event"
}

# ---------------------------------------------------------------------------
# Policy args
# ---------------------------------------------------------------------------
$PolicyArgs = @()
if ($env:LILITH_ZERO_POLICY -and (Test-Path -LiteralPath $env:LILITH_ZERO_POLICY -PathType Leaf)) {
    $PolicyArgs = @('--policy', $env:LILITH_ZERO_POLICY)
}

# ---------------------------------------------------------------------------
# Audit log args
# ---------------------------------------------------------------------------
$AuditArgs = @()
if ($env:LILITH_ZERO_AUDIT) { $AuditArgs = @('--audit-logs', $env:LILITH_ZERO_AUDIT) }

# ---------------------------------------------------------------------------
# Pipe stdin to lilith-zero and relay its stdout
# ---------------------------------------------------------------------------
$stdinContent = $input | Out-String

$argList = @('hook', '--format', 'copilot', '--event', $Event) + $PolicyArgs + $AuditArgs

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName               = $LilithBin
$psi.RedirectStandardInput  = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $false
$psi.UseShellExecute        = $false
$psi.CreateNoWindow         = $true
$psi.Arguments              = ($argList | ForEach-Object { "`"$_`"" }) -join ' '

$proc = [System.Diagnostics.Process]::new()
$proc.StartInfo = $psi

try {
    $null = $proc.Start()
    $proc.StandardInput.Write($stdinContent)
    $proc.StandardInput.Close()

    $stdout = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()

    $line = ($stdout -split "`n" | Where-Object { $_.Trim() -ne '' } | Select-Object -First 1)
    if ($line) {
        Write-Output $line
    } else {
        Deny-Request 'no output from lilith-zero binary'
    }
} catch {
    Deny-Request "failed to run lilith-zero: $_"
} finally {
    if (-not $proc.HasExited) { $proc.Kill() }
    $proc.Dispose()
}

exit 0
