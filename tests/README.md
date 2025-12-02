# Sentinel Tests

This directory contains test files for Sentinel components.

## Test Files

### `test_mcp_jsonrpc.py`

Comprehensive test suite for the MCP JSON-RPC 2.0 implementation.

Tests include:

- `tools/list` endpoint
- `tools/call` with valid token
- `tools/call` with invalid token
- `tools/call` without authorization
- Invalid method handling
- Full interceptor → MCP flow

## Running Tests

Make sure backend services are running, then:

```bash
# From project root
python tests/test_mcp_jsonrpc.py
```

Or with verbose output:

```bash
python tests/test_mcp_jsonrpc.py --verbose
```
