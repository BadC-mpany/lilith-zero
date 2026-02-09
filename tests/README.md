# Lilith Test Suite

Validated security hardening for the Lilith MCP middleware.

## Quickstart

Run all integration tests:
```bash
python -m pytest tests/
```

*Note: The test suite automatically finds the `lilith-zero` binary using the rules defined in the SDK (or `LILITH_ZERO_BINARY_PATH`).*

## Test Modules

### 1. `test_basic_flow.py`
**End-to-End Connectivity Sanity Check.**
- Verifies that the Agent can talk to the Lilith.
- Verifies that Lilith can talk to the Tool Server.
- Verifies basic `tools/list` and `tools/call`.

### 2. `test_security_hardening.py`
**Security Policy Enforcement.**
- **Fail-Closed**: Blocks execution if no policy is present.
- **Taint Tracking**: Verifies that tainted data (e.g., from `read_database`) cannot be passed to sensitive sinks (e.g., `upload`).
- **Resource Globbing**: Checks path-based access controls (`file:///allowed/*`).
- **Spotlighting**: Ensures tool outputs are wrapped in randomized delimiters.
- **Noise Resilience**: Verifies that the protocol adapter handles non-JSON stdout garbage handled gracefully.

## Resources
- `resources/manual_server.py`: A strictly compliant MCP server for testing.
- `resources/noisy_tool.py`: A server that intentionally emits garbage to test protocol robustness.
