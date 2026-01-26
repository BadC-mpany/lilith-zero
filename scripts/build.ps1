Push-Location $PSScriptRoot/../sentinel_middleware
cargo build --release
Pop-Location
Write-Host "Built: sentinel_middleware/target/release/sentinel-interceptor.exe" -ForegroundColor Green
