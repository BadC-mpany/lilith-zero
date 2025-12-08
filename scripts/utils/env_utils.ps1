# scripts/utils/env_utils.ps1
# Robust Python Environment Detection & Execution Utilities

function Get-ProjectRoot {
    # Start looking from the location of this script, or the current directory
    $current = $null
    if ($PSScriptRoot) {
        $current = $PSScriptRoot
    } else {
        $current = Get-Location
    }

    # Walk up the directory tree until we find a marker (sentinel_core or .env)
    while ($current -and (Test-Path $current)) {
        if ((Test-Path (Join-Path $current "sentinel_core")) -or (Test-Path (Join-Path $current ".env"))) {
            return $current
        }
        
        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) {
            break # Reached root of drive
        }
        $current = $parent
    }

    # Fallback to current location if typical markers not found
    return Get-Location
}

function Find-VenvActivationScript {
    param(
        [string]$RootDirectory
    )

    $commonNames = @("sentinel_env", ".venv", "venv", "env")
    
    # 1. Check common names in root first (Fast path)
    foreach ($name in $commonNames) {
        $path = Join-Path $RootDirectory "$name\Scripts\Activate.ps1"
        if (Test-Path $path) {
            Write-Verbose "Found venv at: $path"
            return $path
        }
    }

    # 2. Check for any directory containing Scripts/Activate.ps1 in root
    # Limit depth to avoid scanning node_modules or deep hierarchies
    $candidates = Get-ChildItem -Path $RootDirectory -Directory -ErrorAction SilentlyContinue | 
                  ForEach-Object { Join-Path $_.FullName "Scripts\Activate.ps1" } |
                  Where-Object { Test-Path $_ }
    
    if ($candidates) {
        if ($candidates.Count -gt 1) {
            Write-Warning "Multiple virtual environments found. Using first: $($candidates[0])"
        }
        return $candidates[0]
    }

    return $null
}

function Get-PythonEnvironment {
    $root = Get-ProjectRoot
    $activateScript = Find-VenvActivationScript -RootDirectory $root

    $pythonPath = "python"
    
    # If venv found, verify python inside it
    if ($activateScript) {
        $venvDir = Split-Path -Parent (Split-Path -Parent $activateScript)
        $venvPython = Join-Path $venvDir "Scripts\python.exe"
        if (Test-Path $venvPython) {
            $pythonPath = $venvPython
        }
    }
    
    return @{
        Root = $root
        ActivateScript = $activateScript
        PythonExecutable = $pythonPath
        HasVenv = [bool]$activateScript
    }
}

function Invoke-WithEnvironment {
    <#
    .SYNOPSIS
    Runs a script block with the Python virtual environment activated.
    .EXAMPLE
    Invoke-WithEnvironment -ScriptBlock { python my_script.py }
    #>
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock
    )

    $envInfo = Get-PythonEnvironment

    if ($envInfo.HasVenv) {
        Write-Verbose "Activating environment: $($envInfo.ActivateScript)"
        
        # We need to run this in a way that affects the script block execution
        # Invoking the Activate.ps1 directly in correct scope
        
        # Strategy: capture old env, activate, run, restore (imperfect in PS)
        # OR: simpler approach -> just dot source if valid
        
        # Since we are likely running a python command, 
        # setting VIRTUAL_ENV and updating PATH manually is safer for child processes
        # than trusting Activate.ps1 side effects if we are inside a function.
        
        $venvRoot = Split-Path -Parent (Split-Path -Parent $envInfo.ActivateScript)
        $env:VIRTUAL_ENV = $venvRoot
        $env:PATH = "$venvRoot\Scripts;$env:PATH"
        
        # Run block
        try {
            & $ScriptBlock
        } finally {
            # Cleanup optional? environment variables propagate to process
            # In a script run, this is usually what we want.
        }
    } else {
        Write-Warning "No virtual environment found. Using system Python."
        & $ScriptBlock
    }
}

function Load-EnvFile {
    param(
        [string]$Path
    )

    if (Test-Path $Path) {
        Write-Verbose "Loading .env from $Path"
        Get-Content $Path | ForEach-Object {
            if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim().Trim('"').Trim("'")
                [Environment]::SetEnvironmentVariable($key, $value, "Process")
            }
        }
    }
}

# Export functions to global scope when dot-sourced
# No specific export needed for dot-sourcing, functions become available in the scope they are defined.

