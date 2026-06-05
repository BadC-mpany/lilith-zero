# Lilith-Zero Benchmark and Verification Execution Guide

Follow these steps in order to build, execute, and compile results for all verification suites and performance benchmarks.

---

## Azure Infrastructure State

Current configuration for `lilith-zero.badcompany.xyz` (East US 2, resource group `BadCompany`):

| Setting | Value |
|---|---|
| App Service Plan | B1 Basic, 1 worker (max 3) |
| Always On | Enabled |
| Worker Process | 64-bit |
| Session Storage | Local Ephemeral Disk — `LILITH_ZERO_SESSION_STORAGE_DIR=/tmp/lilith/sessions` |
| Auth Mode | `none` (testing — switch to `entra` for production) |
| Policy Directory | `/app/policies` (baked into container image) |
| Timing Exposure | `LILITH_EXPOSE_TIMING=true` |

> **Note on session storage:** Sessions moved from Azure Files (`/home/.lilith/sessions`, SMB-mounted)
> to local ephemeral disk (`/tmp`). State saves drop from ~17–36 ms to <1 ms. Sessions are lost on
> container restart — acceptable for benchmarking, revisit before production.

---

## 1. Prerequisites, Compilation & Cleaning

Make sure `k6` and `python3` (with `pytest`, `ruff`, and `mypy` installed) are available.

```bash
# A. Build release binary with webhook support enabled
cargo build --release --features webhook

# B. Install Python SDK dev dependencies (if running python tests/tools)
cd sdk && uv pip install -e ".[dev]" && cd ..

# C. Clear old benchmark reports (optional, ensures fresh data generation)
rm -f examples/benchmarks/results/*.json examples/benchmarks/results/*.md
```

---

## 2. CLI Hook Benchmarks

Measure CLI cold-start overhead and policy evaluation latency (runs Claude and Copilot format simulations).

```bash
# Run 10,000 iterations for both hook payload formats with 100 concurrent threads
python3 examples/benchmarks/hook_benchmark.py --iterations 1000 --format all --concurrency 10000
```

---

## 3. Robustness, Differential, and Fuzz Verification

Check for memory safety, file descriptor leaks, differential parity, and input validation.

```bash
# Run robustness tests (concurrency state lock checks, taint persistence)
python3 examples/benchmarks/robustness_test.py

# Run differential matching (CLI vs local Webhook) and adversarial input fuzzing
python3 examples/benchmarks/differential_and_fuzz_test.py --fuzz
```

---

## 4. Local Webhook Load Testing

Simulate high-concurrency requests against a local webhook server.

```bash
# A. Start the local webhook server in the background
LILITH_EXPOSE_TIMING=true ./lilith-zero/target/release/lilith-zero serve \
  --bind 127.0.0.1:8080 \
  --auth-mode none \
  --policy examples/copilot_studio/policies &
SERVER_PID=$!

sleep 1

# B. Static session (high lock contention)
cd examples/benchmarks
LILITH_URL="http://127.0.0.1:8080/analyze-tool-execution" \
LILITH_VUS=100 \
LILITH_DURATION="100s" \
LILITH_RANDOM_CONV=false \
LILITH_AGENT_ID="5be3e14e-2e46-f111-bec6-7c1e52344333,77236ced-1146-f111-bec6-7ced8d71fac9,universal" \
k6 run webhook_load_test.js
cd ../..

# C. Randomized sessions (independent storage writes)
cd examples/benchmarks
LILITH_URL="http://127.0.0.1:8080/analyze-tool-execution" \
LILITH_VUS=1000 \
LILITH_DURATION="100s" \
LILITH_RANDOM_CONV=true \
LILITH_AGENT_ID="5be3e14e-2e46-f111-bec6-7c1e52344333,77236ced-1146-f111-bec6-7ced8d71fac9,universal" \
k6 run webhook_load_test.js
cd ../..

# D. Stop the local server
kill $SERVER_PID
```

---

## 5. Remote Azure Webhook — Phase 1: Baseline (100 VUs)

Establish the baseline after switching from Azure Files to local ephemeral disk.
Compare these numbers against the historical Azure Files results in the results directory.

```bash
# A. Static session (high lock contention)
cd examples/benchmarks
LILITH_URL="https://lilith-zero.badcompany.xyz/analyze-tool-execution" \
LILITH_VUS=150 \
LILITH_DURATION="30s" \
LILITH_RANDOM_CONV=false \
LILITH_AGENT_ID="5be3e14e-2e46-f111-bec6-7c1e52344333,77236ced-1146-f111-bec6-7ced8d71fac9,universal" \
k6 run webhook_load_test.js
cd ../..

# B. Randomized sessions (independent storage writes)
cd examples/benchmarks
LILITH_URL="https://lilith-zero.badcompany.xyz/analyze-tool-execution" \
LILITH_VUS=250 \
LILITH_DURATION="100s" \
LILITH_RANDOM_CONV=true \
LILITH_AGENT_ID="5be3e14e-2e46-f111-bec6-7c1e52344333,77236ced-1146-f111-bec6-7ced8d71fac9,universal" \
k6 run webhook_load_test.js
cd ../..
```

---

## 6. Remote Azure Webhook — Phase 2: B1 Limit Finding

Escalate VUs to find where B1 (1 vCPU, 1.75 GB) saturates. Expect latency to climb and errors
to appear somewhere between 100–300 VUs as Azure App Service's connection queue fills.
Run random sessions only — static sessions serialize on one lock and obscure the infrastructure ceiling.

```bash
# Sweep 1→300 VUs against Azure, 30s per step, random sessions only
python3 examples/benchmarks/run_sweeps.py \
  --url "https://lilith-zero.badcompany.xyz/analyze-tool-execution" \
  --vus "10,100,200,300,500,1000" \
  --duration "30s" \
  --random-only
```

Watch for the inflection point where:
- Error rate > 0%
- P99 latency starts climbing past ~500 ms
- Throughput plateaus or drops

That VU count is the B1 ceiling. Stop here — going higher gives timeout noise, not useful data.

---

## 7. Concurrency & Throughput Parameter Sweeps (Local)

Automate a sweep over multiple VU scales locally to generate performance curves.

```bash
# A. Local sweep (automatically starts & stops the local server)
python3 examples/benchmarks/run_sweeps.py --vus "1,10,100,500,1000,2000" --duration "30s"

# B. Generate latency-concurrency and throughput-latency PNG plots
python3 examples/benchmarks/plot_sweeps.py
```

---

## 8. Compile Reports

Compile all individual results into a single unified Markdown report matrix:

```bash
python3 examples/benchmarks/generate_unified_report.py --random-only
```

The compiled report is generated at `examples/benchmarks/results/unified_benchmark_report.md`.
