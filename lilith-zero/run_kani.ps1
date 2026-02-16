# Helper script to run Kani via Docker on Windows
$ErrorActionPreference = "Stop"

Write-Host "Building Kani Docker image..." -ForegroundColor Cyan
docker build -t lilith-kani -f kani.Dockerfile .


# Define harnesses to run (Skipping HashMap-heavy proofs due to solver timeouts)
$harnesses = @(
    "prove_content_length_no_overflow",
    "prove_session_id_format",
    "prove_taint_clean_logic"
)

$failed = 0

foreach ($harness in $harnesses) {
    Write-Host "Running harness: $harness ..." -ForegroundColor Cyan
    docker run --rm -v "${PWD}:/app" lilith-kani cargo kani --harness $harness
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Harness $harness FAILED!" -ForegroundColor Red
        $failed++
    } else {
        Write-Host "Harness $harness PASSED!" -ForegroundColor Green
    }
}

if ($failed -eq 0) {
    Write-Host "All specified harnesses PASSED!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "$failed harnesses FAILED!" -ForegroundColor Red
    exit 1
}

