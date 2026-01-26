# Rust Interceptor Test Suite

## Overview

This directory contains comprehensive unit and integration tests for the Rust Sentinel Interceptor, following senior-level best practices.

## Test Structure

### Unit Tests (`tests/unit/`)

- **`api/`** - API layer tests (handlers, responses, evaluator adapter, middleware)
- **`auth/`** - Authentication tests (API keys, customer store, policy store, audit logger)
- **`config/`** - Configuration tests
- **`core/`** - Core domain tests (crypto, errors, models)
- **`engine/`** - Policy engine tests (evaluator, pattern matcher, exceptions, tool registry)
- **`proxy/`** - Proxy client tests
- **`state/`** - State management tests (policy cache, session history, redis store)
- **`utils/`** - Utility tests (policy validator, logic pattern args)

### Integration Tests (`tests/integration/`)

- **`test_full_request_flow.rs`** - End-to-end request flow
- **`test_request_id_propagation.rs`** - Request ID tracking
- **`test_policy_introspection.rs`** - Policy introspection endpoint
- **`test_health_check.rs`** - Health check endpoint
- **`test_error_handling.rs`** - Error handling scenarios
- **`test_concurrent_requests.rs`** - Concurrent request handling
- **`test_edge_cases.rs`** - Edge cases and boundary conditions
- **`test_taint_tracking.rs`** - Taint tracking integration
- **`test_policy_evaluation.rs`** - Policy evaluation integration
- **`test_pattern_matching.rs`** - Pattern matching integration
- **`test_mcp_proxy.rs`** - MCP proxy integration
- **`test_proxy_timeout.rs`** - Proxy timeout handling
- **`test_proxy_load.rs`** - Load testing
- **`test_auth_middleware.rs`** - Auth middleware integration
- **`test_config.rs`** - Configuration integration

### Security Tests (`tests/security/`)

- **`test_security.rs`** - Security-focused tests (JWT validation, injection prevention, session isolation)

### Performance Benchmarks (`tests/bench/`)

- **`bench_policy_evaluation.rs`** - Policy evaluation performance
- **`bench_crypto.rs`** - Cryptographic operations performance

### Common Utilities (`tests/common/`)

- **`mod.rs`** - Shared test utilities (mocks, helpers, fixtures)

## Running Tests

### Run All Tests

```bash
cargo test
```

### Run Unit Tests Only

```bash
cargo test --lib
```

### Run Integration Tests Only

```bash
cargo test --test '*'
```

### Run Specific Test Module

```bash
cargo test --lib test_evaluator_adapter
```

### Run Tests with Output

```bash
cargo test -- --nocapture
```

### Run Benchmarks

```bash
cargo bench
```

## Test Coverage

### Current Coverage

- **Unit Tests**: ~250+ test functions
- **Integration Tests**: ~50+ test functions
- **Security Tests**: ~8 test functions
- **Benchmarks**: 2 benchmark suites

### Coverage Goals

- **Code Coverage**: >90% for all modules
- **Branch Coverage**: >85% for critical paths
- **Error Path Coverage**: 100% for all error handlers

## Test Quality Standards

### Naming Convention

- Format: `test_<module>_<functionality>_<scenario>`
- Example: `test_proxy_execute_handler_redis_timeout`

### Test Structure

All tests follow the Arrange-Act-Assert pattern:

```rust
#[tokio::test]
async fn test_example() {
    // Arrange: Set up test data and mocks
    let mock = create_mock();
    
    // Act: Execute the code under test
    let result = function_under_test(&mock).await;
    
    // Assert: Verify the results
    assert!(result.is_ok());
    assert_eq!(result.unwrap().field, expected_value);
}
```

### Documentation

- All tests have doc comments explaining their purpose
- Edge cases are documented
- Test dependencies are clearly stated

## Mock Implementations

Common mocks are available in `tests/common/mod.rs`:

- `MockRedisStore` - Configurable Redis mock
- `MockPolicyStore` - Configurable policy store mock
- `MockCustomerStore` - Configurable customer store mock
- `MockProxyClient` - Configurable proxy client mock
- `MockToolRegistry` - Configurable tool registry mock
- `TestCryptoSigner` - Test crypto signer with known keys

## Test Dependencies

Some tests require external services:

- **Redis Tests**: Require Redis running on `localhost:6379` (or skip if unavailable)
- **Database Tests**: Require PostgreSQL (or use mocks)
- **Integration Tests**: May require full service stack

Tests are designed to gracefully skip if dependencies are unavailable.

## Continuous Integration

All tests should pass in CI environment:

```bash
# CI test command
cargo test --all-features --workspace
```

## Adding New Tests

When adding new functionality:

1. Add unit tests for the new module
2. Add integration tests for new endpoints/flows
3. Add security tests for security-critical paths
4. Update this README if adding new test categories

## Test Maintenance

- Keep tests fast (<1s per test when possible)
- Use mocks for external dependencies
- Avoid test interdependencies
- Clean up test data after each test
- Use unique identifiers to avoid test pollution




