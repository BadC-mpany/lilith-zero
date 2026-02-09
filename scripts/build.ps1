Push-Location $PSScriptRoot/../lilith-zero
cargo build --release
Pop-Location
Write-Host "Built: lilith-zero/target/release/lilith-zero.exe" -ForegroundColor Green
