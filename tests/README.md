# Sentinel Test Suite

Validated security hardening for the Sentinel MCP middleware.

## Running Tests
Ensure you have built the Sentinel binary first:
```bash
cd sentinel
cargo build --release
```

Run all tests from the project root:
```bash
python -m unittest discover tests
```

## Structure
- `test_security_hardening.py`: Deep dive into PII taint tracking, resource blocks, and JWT auth.
- `test_basic_flow.py`: High-level E2E integration sanity check.
- `resources/`: contains the mock tools and noisy upstream simulations.
