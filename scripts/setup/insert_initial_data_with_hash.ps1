# Insert initial data into database using hash from api_key_hash.txt
param(
    [string]$PostgresPassword,
    [string]$ApiKey = "sk_live_demo_123"
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

# Generate hash if not exists
$hashFile = Join-Path $scriptDir "api_key_hash.txt"
if (-not (Test-Path $hashFile)) {
    Write-Host "Generating API key hash..." -ForegroundColor Yellow
    & "$scriptDir\generate_api_key_hash.ps1" -ApiKey $ApiKey
}

# Read hash from file
$hash = Get-Content $hashFile -Raw | ForEach-Object { $_.Trim() }

if ([string]::IsNullOrWhiteSpace($hash)) {
    Write-Host "Error: Could not read hash from $hashFile" -ForegroundColor Red
    exit 1
}

Write-Host "Using API key hash: $hash" -ForegroundColor Cyan

# Read SQL template
$sqlFile = Join-Path $scriptDir "insert_initial_data.sql"
$sqlContent = Get-Content $sqlFile -Raw

# Replace HASH_VALUE with actual hash
$sqlContent = $sqlContent -replace 'HASH_VALUE', $hash

# Create temporary SQL file
$tempSqlFile = Join-Path $scriptDir "insert_initial_data_temp.sql"
$sqlContent | Out-File -FilePath $tempSqlFile -Encoding UTF8

# Set PostgreSQL password
if ($PostgresPassword) {
    $env:PGPASSWORD = $PostgresPassword
}

# Execute SQL
Write-Host "Inserting data into database..." -ForegroundColor Yellow
try {
    psql -U postgres -d sentinel_interceptor -f $tempSqlFile
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Data inserted successfully!" -ForegroundColor Green
    } else {
        Write-Host "Error inserting data. Check PostgreSQL connection." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Error executing SQL: $_" -ForegroundColor Red
    exit 1
} finally {
    # Clean up temp file
    if (Test-Path $tempSqlFile) {
        Remove-Item $tempSqlFile
    }
}

