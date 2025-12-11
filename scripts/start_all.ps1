# scripts/start_all.ps1
# Start all Sentinel services with proper initialization and verification

param(
    [switch]$SkipVerification
)

Write-Host "=== Starting Sentinel Services ===" -ForegroundColor Cyan

# 1. Setup Paths
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Parent $scriptPath
$projectRoot = $scriptDir # scripts is direct child of root check?
# Actually if this is in scripts/, parent is root.
# But original script calculated it via Split-Path -Parent $scriptDir.
# Let's verify.
# If path is C:\...\scripts\start_all.ps1
# $scriptDir is C:\...\scripts
# $projectRoot is C:\...
$projectRoot = Split-Path -Parent $scriptDir

$backendDir = Join-Path $scriptDir "backend"
$utilsDir = Join-Path $scriptDir "utils"

# 2. Redis Setup
$redisMode = $env:REDIS_MODE
if (-not $redisMode) { $redisMode = "docker" }

Write-Host "`n[0] Redis Mode: $redisMode" -ForegroundColor Cyan

if ($redisMode -eq "docker" -or $redisMode -eq "auto") {
    & "$backendDir\start_redis_docker.ps1"
    if ($LASTEXITCODE -ne 0) {
        if ($redisMode -eq "auto") {
            Write-Host "  [WARN] Docker Redis failed, failing over to WSL" -ForegroundColor Yellow
            $redisMode = "wsl"
        } else {
            Write-Error "Docker Redis failed to start."
            exit 1
        }
    }
}

if ($redisMode -eq "wsl") {
    # Check health using new location
    & "$utilsDir\wsl_health_check.ps1" -AutoRecover 2>&1 | Out-Null
    
    # Fix connection
    & "$utilsDir\auto_fix_redis.ps1" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] WSL Redis verified" -ForegroundColor Green
    } else {
        Write-Warning "WSL Redis auto-fix failed. Check manually."
    }
}

# 3. Supabase Connection Check
$envFile = Join-Path $projectRoot ".env"
if (Test-Path $envFile) {
    # Extract SUPABASE_PROJECT_URL from .env
    $supabaseUrl = Get-Content $envFile | Where-Object { $_ -match "^SUPABASE_PROJECT_URL=(.+)" } | ForEach-Object { $matches[1] }
    
    if ($supabaseUrl) {
        Write-Host "  Checking Supabase connectivity..." -NoNewline
        try {
            # Use Head request to check connectivity/DNS
            $check = Invoke-WebRequest -Uri $supabaseUrl -Method Head -TimeoutSec 10 -ErrorAction Stop
            Write-Host " [OK]" -ForegroundColor Green
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 404 -or $_.Exception.Message -match "404") {
                 # 404 means we reached the server, it just didn't like the root path. Good enough!
                 Write-Host " [OK] (Server responded)" -ForegroundColor Green
            } else {
                Write-Host " [WARN]" -ForegroundColor Yellow
                Write-Host "    Could not reach Supabase at $supabaseUrl" -ForegroundColor Yellow
                Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "  [INFO] SUPABASE_PROJECT_URL not found in .env, skipping check." -ForegroundColor Gray
    }
} else {
    Write-Host "  [WARN] .env file not found at $envFile" -ForegroundColor Yellow
}

# 4. Start Services (New Windows)
Write-Host "`n[1] Launching Services..." -ForegroundColor Yellow

# Interceptor
$interceptorWrapper = Join-Path $backendDir "run_interceptor_wrapper.ps1"
if (Test-Path $interceptorWrapper) {
    Start-Process powershell -ArgumentList "-NoExit", "-File", $interceptorWrapper
    Write-Host "  [OK] Interceptor launched" -ForegroundColor Green
} else {
    Write-Error "Interceptor wrapper not found at $interceptorWrapper"
}

# MCP Server
$mcpWrapper = Join-Path $backendDir "run_mcp_wrapper.ps1"
if (Test-Path $mcpWrapper) {
    Start-Process powershell -ArgumentList "-NoExit", "-File", $mcpWrapper
    Write-Host "  [OK] MCP Server launched" -ForegroundColor Green
} else {
    Write-Error "MCP wrapper not found at $mcpWrapper"
}

# 5. Verification
if (-not $SkipVerification) {
    Write-Host "`n[2] Verifying startup..." -ForegroundColor Yellow
    Write-Host "  Waiting for services (max 90s)..." -ForegroundColor Gray
    
    # Simple wait loop
    $maxWait = 90
    $start = Get-Date
    $ready = $false
    
    while ((Get-Date) -lt $start.AddSeconds($maxWait)) {
        $backendOk = $false
        try {
            $r1 = Invoke-WebRequest "http://localhost:8000/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
            if ($r1.StatusCode -eq 200) { $backendOk = $true }
        } catch {}
        
        $mcpOk = $false
        try {
            $r2 = Invoke-WebRequest "http://localhost:9000/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
            if ($r2.StatusCode -eq 200) { $mcpOk = $true }
        } catch {}
        
        if ($backendOk -and $mcpOk) {
            $ready = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    
    if ($ready) {
        Write-Host "  [OK] All services are reachable!" -ForegroundColor Green
        # Optional: run full verify
        # & "$utilsDir\verify_services.ps1"
    } else {
        Write-Host "  [WARN] Services did not become ready in time." -ForegroundColor Yellow
        Write-Host "  Check the other windows for errors." -ForegroundColor Gray
    }
}

Write-Host "`n=== Ready ===" -ForegroundColor Cyan
Write-Host "Run .\scripts\start_agent.ps1 to start the agent." -ForegroundColor White
