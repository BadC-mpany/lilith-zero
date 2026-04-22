# Lilith Zero — VS Code Copilot sidebar hook wrapper (Windows PowerShell)
#
# Called by VS Code for every tool event (PreToolUse, PostToolUse, SessionStart, …).
# Self-discovers the binary and policy — zero configuration needed if you built
# with `cargo build` from the repo root or installed to a known location.
#
# ENV VARS (all optional):
#   LILITH_ZERO_BIN      Override binary path (absolute).
#   LILITH_ZERO_POLICY   Override policy file path (absolute).
#   LILITH_ZERO_EVENT    Event name fallback (VS Code Preview sometimes omits hookEventName).
#   LILITH_ZERO_AUDIT    Path for audit log output.
#   LILITH_ZERO_DEBUG    Set to "1" to print debug info to stderr.
#
# VISIBILITY: add "LILITH_ZERO_DEBUG": "1" to the hooks.json env block,
# then check VS Code Output panel → GitHub Copilot Hooks.
#
# WINDOWS NOTES
#   Run once: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$Debug = $env:LILITH_ZERO_DEBUG -eq '1'
function Write-Debug-Log { param([string]$Msg) if ($Debug) { Write-Error "[lilith-zero] $Msg" } }

# ---------------------------------------------------------------------------
# Fail-closed: emit VS Code deny and exit 0
# ---------------------------------------------------------------------------
function Deny-Request {
    param([string]$Reason = 'internal error')
    $escaped = $Reason -replace '\\', '\\\\' -replace '"', '\"'
    $event = if ($env:LILITH_ZERO_EVENT) { $env:LILITH_ZERO_EVENT } else { 'PreToolUse' }
    Write-Output "{`"hookSpecificOutput`":{`"hookEventName`":`"$event`",`"permissionDecision`":`"deny`",`"permissionDecisionReason`":`"$escaped`"}}"
    exit 0
}

# ---------------------------------------------------------------------------
# Locate the repo root (git rev-parse, fall back to two levels up from script)
# ---------------------------------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
try {
    $GitRoot = (git -C $ScriptDir rev-parse --show-toplevel 2>$null).Trim()
} catch { $GitRoot = $null }
if (-not $GitRoot) {
    $GitRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
}

# ---------------------------------------------------------------------------
# Locate binary
# ---------------------------------------------------------------------------
$LilithBin = $env:LILITH_ZERO_BIN

if (-not $LilithBin) {
    $found = Get-Command 'lilith-zero.exe' -ErrorAction SilentlyContinue
    if ($found) { $LilithBin = $found.Source }
}

if (-not $LilithBin -or -not (Test-Path -LiteralPath $LilithBin -PathType Leaf)) {
    foreach ($candidate in @(
        "$env:USERPROFILE\.local\bin\lilith-zero.exe",
        "$GitRoot\lilith-zero\target\debug\lilith-zero.exe",
        "$GitRoot\lilith-zero\target\release\lilith-zero.exe"
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $LilithBin = $candidate
            break
        }
    }
}

if (-not $LilithBin -or -not (Test-Path -LiteralPath $LilithBin -PathType Leaf)) {
    Deny-Request 'binary not found — run: cd lilith-zero && cargo build'
}

if (-not [System.IO.Path]::IsPathRooted($LilithBin)) {
    Deny-Request 'LILITH_ZERO_BIN must be an absolute path'
}

# ---------------------------------------------------------------------------
# Locate policy
# ---------------------------------------------------------------------------
$Policy = $env:LILITH_ZERO_POLICY
if (-not $Policy -or -not (Test-Path -LiteralPath $Policy -PathType Leaf)) {
    foreach ($candidate in @(
        "$GitRoot\.github\hooks\lilith-policy.yaml",
        "$ScriptDir\policy-static.yaml"
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $Policy = $candidate
            break
        }
    }
}

$PolicyArgs = @()
if ($Policy -and (Test-Path -LiteralPath $Policy -PathType Leaf)) {
    $PolicyArgs = @('--policy', $Policy)
}

# ---------------------------------------------------------------------------
# Event override (belt-and-suspenders: VS Code Preview sometimes omits it)
# ---------------------------------------------------------------------------
$EventArgs = @()
if ($env:LILITH_ZERO_EVENT) {
    $validEvents = @('PreToolUse','PostToolUse','SessionStart','SessionEnd',
                     'UserPromptSubmit','SubagentStart','SubagentStop','Stop','PreCompact')
    $evt = $env:LILITH_ZERO_EVENT
    if ($evt -notin $validEvents) { $evt = 'PreToolUse' }
    $EventArgs = @('--event', $evt)
}

# ---------------------------------------------------------------------------
# Optional audit log
# ---------------------------------------------------------------------------
$AuditArgs = @()
if ($env:LILITH_ZERO_AUDIT) { $AuditArgs = @('--audit-logs', $env:LILITH_ZERO_AUDIT) }

Write-Debug-Log "binary:   $LilithBin"
Write-Debug-Log "policy:   $(if ($Policy) { $Policy } else { '<none — fail-closed>' })"
Write-Debug-Log "event:    $(if ($env:LILITH_ZERO_EVENT) { $env:LILITH_ZERO_EVENT } else { '<from payload>' })"
Write-Debug-Log "git-root: $GitRoot"

# ---------------------------------------------------------------------------
# Pipe stdin to lilith-zero and relay its stdout
# ---------------------------------------------------------------------------
$stdinContent = $input | Out-String

$argList = @('hook', '--format', 'vscode') + $EventArgs + $PolicyArgs + $AuditArgs

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
