# Lilith-Zero Benchmark and Verification Execution Guide

Follow these steps in order to build, execute, and compile results for all verification suites and performance benchmarks.

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
# Run X iterations for both hook payload formats (with X concurrent threads/VUs simulating simultaneous executions)
python3 examples/benchmarks/hook_benchmark.py --iterations 10000 --format all --concurrency 100
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
# A. Start the local webhook server in the background (pointing to the production policies directory)
LILITH_EXPOSE_TIMING=true ./lilith-zero/target/release/lilith-zero serve \
  --bind 127.0.0.1:8080 \
  --auth-mode none \
  --policy examples/copilot_studio/policies &
SERVER_PID=$!

# Wait briefly for server startup
sleep 1

# B. Run local load test with a single static session (high lock contention)
cd examples/benchmarks
LILITH_URL="http://127.0.0.1:8080/analyze-tool-execution" \
LILITH_VUS=100 \
LILITH_DURATION="100s" \
LILITH_RANDOM_CONV=false \
LILITH_AGENT_ID="5be3e14e-2e46-f111-bec6-7c1e52344333,77236ced-1146-f111-bec6-7ced8d71fac9,universal" \
k6 run webhook_load_test.js
cd ../..

# C. Run local load test with randomized sessions (isolated session storage writes)
cd examples/benchmarks
LILITH_URL="http://127.0.0.1:8080/analyze-tool-execution" \
LILITH_VUS=100 \
LILITH_DURATION="100s" \
LILITH_RANDOM_CONV=true \
LILITH_AGENT_ID="5be3e14e-2e46-f111-bec6-7c1e52344333,77236ced-1146-f111-bec6-7ced8d71fac9,universal" \
k6 run webhook_load_test.js
cd ../..

# D. Stop the local webhook server
kill $SERVER_PID
```

---

## 5. Remote Azure Webhook Load Testing
Simulate high-concurrency requests against the live Azure App Service instance.

```bash
# A. Run Azure load test with a single static session
cd examples/benchmarks
LILITH_URL="https://lilith-zero.badcompany.xyz/analyze-tool-execution" \
LILITH_VUS=100 \
LILITH_DURATION="100s" \
LILITH_RANDOM_CONV=false \
LILITH_AGENT_ID="5be3e14e-2e46-f111-bec6-7c1e52344333,77236ced-1146-f111-bec6-7ced8d71fac9,universal" \
k6 run webhook_load_test.js
cd ../..

# B. Run Azure load test with randomized sessions
cd examples/benchmarks
LILITH_URL="https://lilith-zero.badcompany.xyz/analyze-tool-execution" \
LILITH_VUS=100 \
LILITH_DURATION="100s" \
LILITH_RANDOM_CONV=true \
LILITH_AGENT_ID="5be3e14e-2e46-f111-bec6-7c1e52344333,77236ced-1146-f111-bec6-7ced8d71fac9,universal" \
k6 run webhook_load_test.js
cd ../..
```

---

## 6. Concurrency & Throughput Parameter Sweeps
Automate a sweep over multiple Virtual User (VU) scales and session storage modes to generate performance curves.

```bash
# A. Execute the parameter sweeps locally (automatically starts & stops the local server)
python3 examples/benchmarks/run_sweeps.py --vus "1,10,100, 500, 1000, 2000, 5000, 10000" --duration "100s"

# B. (Optional) Run the parameter sweeps against the Azure deployment
python3 examples/benchmarks/run_sweeps.py --url "https://lilith-zero.badcompany.xyz/analyze-tool-execution" --vus "1,10,100, 500, 1000, 2000, 5000, 10000" --duration "20s"

# C. Generate the latency-concurrency and throughput-latency PNG plots
python3 examples/benchmarks/plot_sweeps.py
```

---

## 7. Compile Reports

Compile the individual results from the runs into a single, unified Markdown report matrix:

```bash
python3 examples/benchmarks/generate_unified_report.py
```

The compiled report is generated at `examples/benchmarks/results/unified_benchmark_report.md`.

