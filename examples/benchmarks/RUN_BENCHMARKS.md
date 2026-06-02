# Lilith-Zero Benchmark and Verification Execution Guide

Follow these steps in order to build, execute, and compile results for all verification suites and performance benchmarks.

---

## 1. Prerequisites & Compilation

Make sure `k6` and `python3` (with `pytest`, `ruff`, and `mypy` installed) are available.

```bash
# Build release binary with webhook support enabled
cargo build --release --features webhook

# Install Python SDK dev dependencies (if running python tests/tools)
cd sdk && uv pip install -e ".[dev]" && cd ..
```

---

## 2. CLI Hook Benchmarks
Measure CLI cold-start overhead and policy evaluation latency (runs Claude and Copilot format simulations).

```bash
# Run 200 iterations for both hook payload formats
python3 examples/benchmarks/hook_benchmark.py --iterations 200 --format all
```

---

## 3. Robustness, Differential, and Fuzz Verification
Check for memory safety, file descriptor leaks, differential parity, and inputs validation.

```bash
# Run robustness tests (concurrency state lock checks, taint persistence)
python3 examples/benchmarks/robustness_test.py

# Run differential matching (CLI vs Webhook) and adversarial input fuzzing
python3 examples/benchmarks/differential_and_fuzz_test.py --fuzz
```

---

## 4. Local Webhook Load Testing
Simulate high-concurrency requests against a local webhook server.

```bash
# A. Start the local webhook server in the background
./lilith-zero/target/release/lilith-zero serve \
  --bind 127.0.0.1:8080 \
  --auth-mode none \
  --policy examples/benchmarks/benchmark_policy.cedar &
SERVER_PID=$!

# Wait briefly for server startup
sleep 1

# B. Run local load test with a single static session (high lock contention)
LILITH_URL="http://127.0.0.1:8080/analyze-tool-execution" \
LILITH_VUS=10 \
LILITH_DURATION="10s" \
LILITH_RANDOM_CONV=false \
LILITH_AGENT_ID="benchmark_policy" \
k6 run --directory examples/benchmarks examples/benchmarks/webhook_load_test.js

# C. Run local load test with randomized sessions (isolated session storage writes)
LILITH_URL="http://127.0.0.1:8080/analyze-tool-execution" \
LILITH_VUS=10 \
LILITH_DURATION="10s" \
LILITH_RANDOM_CONV=true \
LILITH_AGENT_ID="benchmark_policy" \
k6 run --directory examples/benchmarks examples/benchmarks/webhook_load_test.js

# D. Stop the local webhook server
kill $SERVER_PID
```

---

## 5. Remote Azure Webhook Load Testing
Simulate high-concurrency requests against the live Azure App Service instance.

```bash
# A. Run Azure load test with a single static session
LILITH_URL="https://lilith-zero.badcompany.xyz/analyze-tool-execution" \
LILITH_VUS=10 \
LILITH_DURATION="10s" \
LILITH_RANDOM_CONV=false \
LILITH_AGENT_ID="5be3e14e-2e46-f111-bec6-7c1e52344333" \
k6 run --directory examples/benchmarks examples/benchmarks/webhook_load_test.js

# B. Run Azure load test with randomized sessions
LILITH_URL="https://lilith-zero.badcompany.xyz/analyze-tool-execution" \
LILITH_VUS=10 \
LILITH_DURATION="10s" \
LILITH_RANDOM_CONV=true \
LILITH_AGENT_ID="5be3e14e-2e46-f111-bec6-7c1e52344333" \
k6 run --directory examples/benchmarks examples/benchmarks/webhook_load_test.js
```

---

## 6. Compile Reports

Compile the individual results from the runs into a single, unified Markdown report matrix:

```bash
python3 examples/benchmarks/generate_unified_report.py
```

The compiled report is generated at `examples/benchmarks/results/unified_benchmark_report.md`.
