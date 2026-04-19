# Lilith Zero — GitHub Copilot hook wrapper (Windows PowerShell)
#
# PURPOSE
#   This script is the entry point configured in .github/hooks/hooks.json
#   for every Copilot hook event on Windows. It locates the lilith-zero binary,
#   validates the path, and forwards stdin to the security engine.
#
# SECURITY DESIGN
#   - Fail-closed: if the binary is not found or its path is not absolute,
#     we write a deny decision to stdout and exit 0. We never allow by default.
#   - No Invoke-Expression or dynamic command construction from external input.
#   - Binary path must be absolute (rooted) to prevent workspace file shadowing.
#   - The policy path is passed only as a flag, never executed.
#   - Output uses Write-Output (not Write-Host) so it goes to stdout, not the
#     console host — required for Copilot to read the decision.
#
# CONFIGURATION (via environment variables)
#   LILITH_ZERO_BIN      Absolute path to lilith-zero.exe.
#                        Default: first lilith-zero.exe found on $env:PATH.
#   LILITH_ZERO_POLICY   Absolute path to the policy YAML file.
#                        Default: .github\hooks\lilith-policy.yaml in the repo root.
#   LILITH_ZERO_EVENT    Copilot event name (preToolUse | postToolUse | sessionStart | sessionEnd).
#                        Must be set via the `env` field in hooks.json.
#   LILITH_ZERO_AUDIT    Path for the audit log file. Optional.
#
# USAGE (in .github/hooks/hooks.json)
#   {
#     "version": 1,
#     "hooks": {
#       "preToolUse": [{
#         "type": "command",
#         "powershell": ".github/hooks/hook-wrapper.ps1",
#         "env": { "LILITH_ZERO_EVENT": "preToolUse" },
#         "timeoutSec": 10
#       }]
#     }
#   }
#
# WINDOWS NOTES
#   - Run: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
#     (or deploy via Group Policy for managed endpoints).
#   - The binary must be code-signed for enterprise deployments.

#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Fail-closed helper
# ---------------------------------------------------------------------------
function Deny-Request {
    param([string]$Reason = 'unknown error')
    # JSON-escape the reason: replace backslash then double-quote
    $escaped = $Reason -replace '\\', '\\' -replace '"', '\"'
    Write-Output "{`"permissionDecision`":`"deny`",`"permissionDecisionReason`":`"$escaped`"}"
    exit 0
}

# ---------------------------------------------------------------------------
# Locate lilith-zero binary
# ---------------------------------------------------------------------------
$LilithBin = $env:LILITH_ZERO_BIN

if (-not $LilithBin) {
    $found = Get-Command 'lilith-zero.exe' -ErrorAction SilentlyContinue
    if ($found) {
        $LilithBin = $found.Source
    }
}

if (-not $LilithBin) {
    Deny-Request 'lilith-zero binary not found: set LILITH_ZERO_BIN or add it to PATH'
}

# ---------------------------------------------------------------------------
# Security: require an absolute (rooted) path
# ---------------------------------------------------------------------------
if (-not [System.IO.Path]::IsPathRooted($LilithBin)) {
    Deny-Request "LILITH_ZERO_BIN must be an absolute path, got: $LilithBin"
}

if (-not (Test-Path -LiteralPath $LilithBin -PathType Leaf)) {
    Deny-Request "lilith-zero binary not found at: $LilithBin"
}

# ---------------------------------------------------------------------------
# Resolve format and event name
# ---------------------------------------------------------------------------
$Format = $env:LILITH_ZERO_FORMAT
if (-not $Format) { $Format = 'copilot' }

$ValidFormats = @('copilot', 'vscode')
if ($Format -notin $ValidFormats) {
    Deny-Request "Invalid LILITH_ZERO_FORMAT value: $Format (must be copilot or vscode)"
}

$Event = $env:LILITH_ZERO_EVENT
$EventArgs = @()

if ($Format -eq 'copilot') {
    if (-not $Event) {
        Deny-Request 'LILITH_ZERO_EVENT must be set for --format copilot (e.g. preToolUse, postToolUse)'
    }
    $ValidEvents = @('preToolUse', 'postToolUse', 'sessionStart', 'sessionEnd', 'userPromptSubmitted', 'errorOccurred')
    if ($Event -notin $ValidEvents) {
        Deny-Request "Invalid LILITH_ZERO_EVENT value: $Event"
    }
    $EventArgs = @('--event', $Event)
} elseif ($Event) {
    $ValidVsCodeEvents = @('PreToolUse', 'PostToolUse', 'SessionStart', 'SessionEnd', 'UserPromptSubmit', 'SubagentStart', 'SubagentStop', 'Stop', 'PreCompact')
    if ($Event -notin $ValidVsCodeEvents) {
        Deny-Request "Invalid LILITH_ZERO_EVENT value: $Event"
    }
    $EventArgs = @('--event', $Event)
}

# ---------------------------------------------------------------------------
# Resolve policy file
# ---------------------------------------------------------------------------
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$DefaultPolicy = Join-Path $RepoRoot '.github\hooks\lilith-policy.yaml'

$Policy = $env:LILITH_ZERO_POLICY
if (-not $Policy) { $Policy = $DefaultPolicy }

$PolicyArgs = @()
if ($Policy -and (Test-Path -LiteralPath $Policy -PathType Leaf)) {
    if (-not [System.IO.Path]::IsPathRooted($Policy)) {
        Deny-Request 'LILITH_ZERO_POLICY must be an absolute path'
    }
    $PolicyArgs = @('--policy', $Policy)
}

# ---------------------------------------------------------------------------
# Resolve optional audit log path
# ---------------------------------------------------------------------------
$AuditArgs = @()
if ($env:LILITH_ZERO_AUDIT) {
    $AuditArgs = @('--audit-logs', $env:LILITH_ZERO_AUDIT)
}

# ---------------------------------------------------------------------------
# Read stdin and pipe to lilith-zero
#
# PowerShell does not support exec-style process replacement, so we spawn a
# child process, pipe stdin, and relay stdout. We use -NoNewWindow and
# -RedirectStandardInput to ensure the hook JSON payload reaches the binary.
# ---------------------------------------------------------------------------
$stdinContent = $input | Out-String

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName               = $LilithBin
$psi.RedirectStandardInput  = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $false  # let stderr pass through for audit/debug logs
$psi.UseShellExecute        = $false
$psi.CreateNoWindow         = $true

# Build argument list safely (no string concatenation of untrusted input)
$argList = @('hook', '--format', $Format) + $EventArgs + $PolicyArgs + $AuditArgs
$psi.Arguments = ($argList | ForEach-Object { "`"$_`"" }) -join ' '

$proc = [System.Diagnostics.Process]::new()
$proc.StartInfo = $psi

try {
    $null = $proc.Start()
    $proc.StandardInput.WriteLine($stdinContent)
    $proc.StandardInput.Close()

    $stdout = $proc.StandardOutput.ReadToEnd()
    $proc.WaitForExit()

    # Relay the JSON line to our stdout (Copilot reads from here)
    $line = ($stdout -split "`n" | Where-Object { $_.Trim() -ne '' } | Select-Object -First 1)
    if ($line) {
        Write-Output $line
    } else {
        Deny-Request 'no output from lilith-zero binary'
    }
} catch {
    Deny-Request "failed to run lilith-zero: $_"
} finally {
    if (-not $proc.HasExited) {
        $proc.Kill()
    }
    $proc.Dispose()
}

exit 0
