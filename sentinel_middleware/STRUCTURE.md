# Sentinel Interceptor: Rust Implementation Architecture

**Version:** 0.1.0  
**Target:** Production-grade Zero Trust security enforcement layer  
**Performance Target:** 10,000+ RPS per instance, <5ms p99 latency  
**Security Model:** Fail-closed, cryptographic binding, stateful taint tracking

---

## Executive Summary

Architectural blueprint for Sentinel Interceptor Rust implementation following **Domain-Driven Design (DDD)** with strict separation between pure domain logic and I/O-bound operations. Implements **Zero Trust** security model: deterministic policy evaluation, cryptographic token binding, stateful taint tracking.

**Core Design Principles:**

- **Memory Safety:** Rust ownership system eliminates use-after-free, double-free, data races
- **Zero-Cost Abstractions:** O(1) static rule lookups, O(n) dynamic rule evaluation
- **Fail-Closed Security:** Any failure results in denial, never unauthorized access
- **Async-First Concurrency:** Fully non-blocking I/O using Tokio work-stealing scheduler

---

## Architectural Overview

### Layered Architecture (Tower Pattern)

Composable middleware stack following Tower service pattern:

```
Transport Layer (Hyper)
├─ HTTP/1.1 & HTTP/2 multiplexing
└─ Connection pooling & keep-alive
         ↓
Protective Middleware Stack
├─ Rate Limiting (tower_governor: Leaky Bucket)
├─ Request Timeout (30s global, 5s MCP proxy)
├─ Body Size Limits (2MB max)
└─ Panic Recovery (tower::util::BoxLayer)
         ↓
Observability Middleware
├─ Distributed Tracing (tower-http::trace)
├─ Prometheus Metrics (custom registry)
└─ Structured Logging (tracing + JSON)
         ↓
Application Layer (Axum Handlers)
├─ Request deserialization (serde_json)
├─ Policy evaluation (pure Rust, no I/O)
├─ Cryptographic token minting (Ed25519)
└─ MCP proxy forwarding (Reqwest)
         ↓
State Management Layer
├─ Redis (session taints, history)
├─ Moka Cache (policy lookups, TTL-based)
└─ Connection Pooling (bb8-redis)
```

---

## Module Architecture & Technical Specifications

### Module 1: `core` - Domain Kernel

Pure Rust domain logic with zero I/O dependencies. Single source of truth for business rules and cryptographic operations.

**Memory Safety Guarantees:**

- All types implement `Send + Sync` for safe cross-thread sharing
- No `unsafe` blocks (except cryptographic library requirements)
- `secrecy::Secret<T>` for sensitive data (prevents accidental logging)

#### `models.rs` - Domain Entities

```rust
// Newtype pattern for type safety
pub struct SessionId(Uuid);

// Zero-copy deserialization where possible
pub struct ToolCall {
    pub tool_name: String,           // Owned (required for hashing)
    pub args: serde_json::Value,     // Owned (required for canonicalization)
}

// Enum-based policy rules (make invalid states unrepresentable)
pub enum Decision {
    Allowed,
    Denied { reason: String },
    AllowedWithSideEffects {
        taints_to_add: Vec<String>,
        taints_to_remove: Vec<String>,
    },
}
```

**Design Rationale:**

- Newtype wrappers prevent primitive obsession, enable type-safe APIs
- Enum-based decisions leverage exhaustive pattern matching
- Owned strings required for cryptographic operations; optimize with `Cow<str>` in future

#### `crypto.rs` - Cryptographic Primitives

**Security Properties:**

- **Ed25519 Signatures:** Post-quantum resistant, deterministic (no nonce required)
- **RFC 8785 JCS Canonicalization:** Mathematically guarantees identical JSON produces identical bytes
- **SHA-256 Parameter Hashing:** Prevents TOCTOU attacks

**Implementation:**

```rust
pub struct CryptoSigner {
    signing_key: Secret<SigningKey>,  // Memory-protected private key
}

impl CryptoSigner {
    // Constant-time operations (no secret-dependent branches)
    pub fn mint_token(&self, session_id: &str, tool_name: &str, args: &Value) -> Result<String>

    // Deterministic canonicalization (RFC 8785)
    pub fn canonicalize(data: &Value) -> Result<Vec<u8>>

    // Parameter integrity binding
    pub fn hash_params(args: &Value) -> Result<String>
}
```

**Performance Characteristics:**

- Token minting: ~50-100μs (Ed25519 signing)
- Parameter hashing: ~10-20μs (SHA-256 of canonicalized JSON)
- Canonicalization: O(n) where n is JSON size, typically <100μs for typical tool args

#### `errors.rs` - Error Domain Model

```rust
#[derive(Error, Debug)]
pub enum InterceptorError {
    #[error("Invalid API Key")]
    InvalidApiKey,                    // 401

    #[error("Policy violation: {0}")]
    PolicyViolation(String),          // 403

    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] CryptoError),  // 500

    #[error("MCP proxy error: {0}")]
    McpProxyError(String),            // 502
}
```

**Security Considerations:**

- No stack traces exposed to clients (prevents information disclosure)
- Generic error messages for authentication failures (prevents user enumeration)
- Detailed errors logged server-side only (structured JSON logs)

---

### Module 2: `state` - State Management & Caching

Manages persistent state (Redis) and in-memory caching (Moka) with connection pooling and atomic operations.

#### `redis_store.rs` - Redis Operations

**Connection Pooling:**

- **bb8-redis:** Async connection pool with automatic reconnection
- **Pool Size:** 20 connections (configurable via env)
- **Connection Timeout:** 2s (fail fast)
- **Idle Timeout:** 90s (reuse connections)

**Atomic Operations:**

```rust
// Atomic taint operations using Redis transactions
pub async fn add_taint_atomic(&self, session_id: &str, tag: &str) -> Result<()> {
    // Uses MULTI/EXEC or Lua script for atomicity
    // Prevents race conditions in concurrent requests
}
```

**Data Structures:**

- **Session Taints:** Redis SET (`session:{id}:taints`) with TTL
- **Session History:** Redis LIST (`session:{id}:history`) with LRU trimming (last 1000 entries)
- **Nonce Cache:** Redis STRING (`nonce:{jti}`) with TTL matching token expiry

**Performance Targets:**

- Taint lookup: <1ms (local Redis)
- History append: <2ms (async, fire-and-forget)
- Atomic operations: <5ms (Lua script execution)

#### `policy_cache.rs` - In-Memory Policy Cache

**Caching Strategy:**

- **Cache Library:** Moka (high-performance concurrent cache)
- **Key:** API Key SHA-256 hash (prevent timing attacks)
- **Value:** `Arc<PolicyDefinition>` (shared ownership, zero-copy reads)
- **TTL:** Configurable (default: 60s)
- **Max Capacity:** 1000 policies (LRU eviction)

**Cache Invalidation:**

- Time-based (TTL expiration)
- Manual invalidation on policy updates (future: watch file system or Redis pub/sub)

**Performance Characteristics:**

- Cache hit: <100ns (in-memory HashMap lookup)
- Cache miss: ~1-2ms (YAML file read + parse)

---

### Module 3: `engine` - Policy Evaluation Engine

Deterministic state machine evaluating security policies against tool execution requests.

#### `evaluator.rs` - Rule Evaluation Logic

**Evaluation Pipeline:**

```
1. Static Rule Check (O(1))
   └─> HashMap lookup: tool_name -> ALLOW/DENY
   └─> Early return if DENY

2. Dynamic Taint Rule Check (O(n) where n = number of taint rules)
   └─> For each taint rule:
       ├─> Pattern-based rules (sequence, logic)
       └─> Simple taint rules (ADD_TAINT, CHECK_TAINT, REMOVE_TAINT)

3. Decision Aggregation
   └─> Collect side effects (taints to add/remove)
   └─> Return Decision enum
```

**Complexity Analysis:**

- **Best Case:** O(1) - Static DENY rule matches
- **Average Case:** O(n) where n = number of active taint rules (typically 5-10)
- **Worst Case:** O(n\*m) where n = taint rules, m = history entries (pattern matching)

**Optimization Opportunities:**

- Early termination on first DENY
- Rule indexing by tool name/class (future)
- Pattern matching optimization with finite state machines (future)

#### `pattern_matcher.rs` - Advanced Pattern Matching

**Pattern Types:**

1. **Sequence Patterns:**

   - Detects ordered sequences of tool executions
   - Supports `max_distance` constraint
   - Example: Block `CONSEQUENTIAL_WRITE` after `SENSITIVE_READ`

2. **Logic Patterns:**
   - Boolean logic over session state
   - Supports AND, OR, NOT operators
   - Example: Block `HUMAN_VERIFY` if session has `SENSITIVE_READ` AND current tool is `HUMAN_VERIFY`

**Implementation Strategy:**

- Recursive descent parser for logic expressions
- Sliding window algorithm for sequence detection
- Memoization of history queries (future optimization)

---

### Module 4: `loader` - Configuration Loading

Loads security policies and tool registries from YAML files with validation and error handling.

#### `policy_loader.rs` - Policy Deserialization

**Loading Strategy:**

- **File Discovery:** Multiple fallback paths (env var, project root, Docker path)
- **Deserialization:** `serde_yaml` with strict validation
- **Error Handling:** Detailed error messages with file path and line number

**Data Structures:**

- `HashMap<String, CustomerConfig>` - API key -> customer mapping
- `HashMap<String, PolicyDefinition>` - Policy name -> policy mapping
- `HashMap<String, Vec<String>>` - Tool name -> security classes mapping

**Validation:**

- Required fields present
- Valid enum values (ALLOW/DENY, action types)
- Valid URLs for MCP upstream
- No circular policy references

---

### Module 5: `auth` - Authentication & Authorization

Production-ready API key management with database-backed storage, constant-time comparison, and two-level caching.

#### `api_key.rs` - API Key Hashing & Validation

**Security Properties:**

- **SHA-256 Hashing:** Prevents timing attacks via constant-time lookup
- **Hash-Based Lookup:** Eliminates string comparison timing leaks
- **Never Store Plaintext:** Keys hashed immediately upon receipt

**Implementation:**

```rust
use sha2::{Sha256, Digest};
use secrecy::Secret;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApiKeyHash(String);

impl ApiKeyHash {
    /// Hash API key using SHA-256 (constant-time operation)
    pub fn from_api_key(api_key: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        Self(hex::encode(hasher.finalize()))
    }
}

pub struct ApiKey(Secret<String>);

impl ApiKey {
    pub fn hash(&self) -> ApiKeyHash {
        ApiKeyHash::from_api_key(self.expose_secret())
    }

    /// Constant-time comparison (prevents timing attacks)
    pub fn constant_time_eq(&self, other: &str) -> bool {
        self.expose_secret().as_bytes().ct_eq(other.as_bytes()).into()
    }
}
```

**Performance Characteristics:**

- Key hashing: ~5-10μs (SHA-256)
- Hash lookup: O(1) with database index
- Constant-time comparison: <100ns

#### `customer_store.rs` - Database-Backed Customer Storage

**Two-Level Caching Strategy:**

- **L1 Cache (Moka):** In-memory cache with TTL (5 minutes)
- **L2 Cache (Database):** PostgreSQL with indexed hash lookup

**Database Schema:**

```sql
CREATE TABLE customers (
    id UUID PRIMARY KEY,
    api_key_hash VARCHAR(64) UNIQUE NOT NULL,  -- SHA-256 hex
    owner VARCHAR(255) NOT NULL,
    mcp_upstream_url TEXT NOT NULL,
    policy_name VARCHAR(255) NOT NULL,
    revoked_at TIMESTAMPTZ,  -- Soft delete for key rotation
    last_used_at TIMESTAMPTZ,
    INDEX idx_api_key_hash (api_key_hash) WHERE revoked_at IS NULL
);
```

**Implementation:**

```rust
pub struct CustomerStore {
    db_pool: PgPool,
    cache: Cache<String, Arc<CustomerConfig>>,  // Key: api_key_hash
}

impl CustomerStore {
    pub async fn lookup_customer(
        &self,
        api_key_hash: &ApiKeyHash,
    ) -> Result<Option<CustomerConfig>, sqlx::Error> {
        // 1. Check cache (O(1) in-memory lookup)
        if let Some(cached) = self.cache.get(api_key_hash.as_str()).await {
            return Ok(Some((*cached).clone()));
        }

        // 2. Query database (indexed hash lookup)
        let customer = sqlx::query_as!(
            CustomerConfig,
            "SELECT id, owner, mcp_upstream_url, policy_name, last_used_at
             FROM customers WHERE api_key_hash = $1 AND revoked_at IS NULL",
            api_key_hash.as_str()
        )
        .fetch_optional(&self.db_pool)
        .await?;

        // 3. Update cache if found
        if let Some(ref config) = customer {
            self.cache.insert(
                api_key_hash.as_str().to_string(),
                Arc::new(config.clone()),
            ).await;
        }

        Ok(customer)
    }
}
```

**Performance Targets:**

- Cache hit: <100ns (in-memory HashMap)
- Cache miss: <5ms (database query with index)
- Cache hit rate: High under normal load

#### `policy_store.rs` - Database-Backed Policy Storage

**Policy Loading with Cache:**

```rust
pub struct PolicyStore {
    db_pool: PgPool,
    cache: Cache<String, Arc<PolicyDefinition>>,  // Key: policy_name
}

impl PolicyStore {
    pub async fn load_policy(
        &self,
        policy_name: &str,
    ) -> Result<Option<PolicyDefinition>, sqlx::Error> {
        // Cache-first lookup with database fallback
        // JSONB storage for flexible policy structure
    }
}
```

**Database Schema:**

```sql
CREATE TABLE policies (
    name VARCHAR(255) PRIMARY KEY,
    static_rules JSONB NOT NULL,
    taint_rules JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

#### `auth_middleware.rs` - Authentication Middleware

**Axum Middleware for Request Authentication:**

```rust
pub async fn auth_middleware(
    State(state): State<Arc<AuthState>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<Value>)> {
    // 1. Extract API key from header
    // 2. Hash API key (constant-time)
    // 3. Lookup customer (cache-first)
    // 4. Load policy (cache-first)
    // 5. Attach to request extensions
    // 6. Log authentication event
}
```

**Security Features:**

- Constant-time API key hashing
- Generic error messages (prevents user enumeration)
- Audit logging for all authentication events
- Fail-closed on any error

#### `audit_logger.rs` - Security Event Logging

**Audit Trail:**

```sql
CREATE TABLE auth_audit_log (
    id UUID PRIMARY KEY,
    api_key_hash VARCHAR(64),
    event_type VARCHAR(50) NOT NULL,  -- 'AUTH_SUCCESS', 'AUTH_FAILURE'
    ip_address INET,
    user_agent TEXT,
    session_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

**Implementation:**

- Fire-and-forget async logging
- Structured JSON logs
- Rate limit detection
- Security event correlation

**Security Hardening:**

- **Timing Attack Prevention:** Constant-time operations throughout
- **Key Storage:** Never store plaintext keys, hash immediately
- **Key Rotation:** Soft delete with `revoked_at`, audit trail maintained
- **Database Security:** TLS connections, prepared statements, read-only user

**Migration Path:**

- Phase 1: Dual mode (Database + YAML fallback)
- Phase 2: Database migration script
- Phase 3: Remove YAML support

---

### Module 6: `api` - HTTP API Layer

Axum-based HTTP server with middleware stack and request handlers.

#### `handlers.rs` - Request Processing

**Request Flow:**

```rust
async fn proxy_execute_handler(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProxyRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // 1. Extract & validate API key (constant-time comparison)
    // 2. Load policy from cache (O(1) cache lookup)
    // 3. Fetch session state from Redis (async I/O)
    // 4. Evaluate policy (pure Rust, <1ms)
    // 5. Mint JWT token (cryptographic operation, ~100μs)
    // 6. Forward to MCP server (network I/O, ~10-50ms)
    // 7. Update state asynchronously (fire-and-forget)
    // 8. Return response
}
```

**Error Handling:**

- All errors mapped to appropriate HTTP status codes
- Generic error messages to clients
- Detailed errors logged server-side

#### `middleware.rs` - Security & Observability Middleware

**Middleware Stack:**

1. **Rate Limiting (`tower_governor`):**

   - Algorithm: Leaky Bucket
   - Key: Customer ID (from API key)
   - Limits: Configurable per customer

2. **Request Timeout (`tower::timeout`):**

   - Global timeout: Configurable (default: 30s)
   - Prevents resource exhaustion

3. **Body Size Limit (`tower::limit`):**

   - Max size: 2MB
   - Prevents memory exhaustion attacks

4. **Tracing (`tower-http::trace`):**
   - Request ID generation
   - Structured logging
   - Performance metrics

---

### Module 7: `proxy` - MCP Proxy Client

HTTP client for forwarding requests to upstream MCP servers with connection pooling.

#### `client.rs` - HTTP Client Configuration

**Connection Pooling:**

- **Library:** Reqwest with connection pool
- **Pool Size:** Configurable (default: 100 connections)
- **Idle Timeout:** Configurable (default: 90s)
- **TCP_NODELAY:** Enabled (reduce latency)

**Protocol Compliance:**

- JSON-RPC 2.0 request format
- Bearer token authentication
- Proper error code mapping
- Request/response correlation via `id` field

**Retry Strategy:**

- No automatic retries (fail fast)
- Timeout: Configurable (default: 5s per request)
- Error propagation to interceptor

---

## Testing Strategy

### Unit Tests (`tests/unit/`)

**Coverage Targets:**

- Crypto operations: Complete coverage (critical security code)
- Policy evaluator: All decision paths covered
- Pattern matcher: All pattern types covered

**Test Philosophy:**

- Property-based testing for cryptographic operations
- Table-driven tests for policy evaluation
- Fuzz testing for JSON deserialization

### Integration Tests (`tests/integration/`)

**Test Scenarios:**

1. Policy Evaluation: End-to-end policy enforcement
2. Taint Tracking: State persistence across requests
3. Pattern Matching: Sequence and logic pattern detection
4. MCP Proxy: JSON-RPC 2.0 protocol compliance

**Test Infrastructure:**

- Embedded Redis for state tests
- Mock MCP server (Mockito) for proxy tests
- Test fixtures for policy configurations

### Benchmarks (`benches/`)

**Performance Benchmarks:**

- Cryptographic operations (token minting, hashing)
- Policy evaluation (various rule configurations)
- Redis operations (taint lookups, history appends)

**Target Metrics:**

- Token minting: <100μs p99
- Policy evaluation: <1ms p99
- Redis operations: <2ms p99

---

## Security Hardening

### Secret Management

- **Private Keys:** Loaded into `secrecy::Secret<T>` wrapper
- **API Keys:** Hashed (SHA-256) before storage, constant-time comparison
- **Database Storage:** PostgreSQL with indexed hash lookups, TLS connections
- **Key Rotation:** Soft delete with audit trail, cache invalidation
- **Memory Protection:** Attempts to prevent swapping (platform-dependent)

### Input Validation

- **Request Size:** 2MB maximum body size
- **JSON Validation:** Strict deserialization with `serde`
- **Parameter Validation:** Tool-specific argument validation (future)

### Error Handling

- **No Information Disclosure:** Generic error messages to clients
- **Structured Logging:** JSON logs with sanitized data
- **Error Classification:** Proper HTTP status codes

### Denial of Service Protection

- **Rate Limiting:** Per-customer request limits
- **Timeouts:** Global and per-operation timeouts
- **Connection Limits:** Max connections per customer (future)

---

## Performance Characteristics

### Latency Breakdown (p99)

```
Request Processing Pipeline:
├─ API Key Hashing:           <10μs   (SHA-256)
├─ Customer Lookup:           <100μs  (cache hit) or <5ms (cache miss, DB)
├─ Policy Loading:            <100μs  (cache hit) or <5ms (cache miss, DB)
├─ Redis Taint Fetch:         <2ms    (async I/O)
├─ Policy Evaluation:          <1ms    (pure Rust)
├─ Token Minting:             <100μs  (Ed25519 signing)
├─ MCP Proxy Forward:         <50ms   (network I/O)
└─ State Update (async):      <1ms    (fire-and-forget)

Total:                        <60ms   (p99, excluding network)
```

### Throughput

- **Target:** 10,000+ RPS per instance
- **Bottleneck:** MCP proxy network I/O (can be parallelized)
- **Scaling:** Horizontal scaling via load balancer

### Resource Usage

- **Memory:** <100MB baseline, <500MB under load
- **CPU:** Low utilization at 1k RPS, moderate at 10k RPS
- **Connections:** ~20 Redis connections, ~100 HTTP connections, ~20 PostgreSQL connections

---

## Directory Structure

```
sentinel_core/interceptor/rust/
├── Cargo.toml                    # Dependencies, features, workspace config
├── Dockerfile                     # Multi-stage build (builder + distroless)
├── .dockerignore                  # Docker build exclusions
├── .gitignore                     # Git exclusions
├── README.md                      # Project documentation
├── STRUCTURE.md                   # This document
│
├── src/                           # Source code (Rust modules)
│   ├── main.rs                    # Application entry point, server bootstrap
│   ├── lib.rs                     # Library root, public API
│   ├── config.rs                  # Configuration management (env vars, file loading)
│   │
│   ├── core/                      # Domain kernel (pure Rust, zero I/O)
│   │   ├── mod.rs                 # Module declarations, re-exports
│   │   ├── models.rs              # Domain entities (SessionId, ToolCall, Policy, Decision)
│   │   ├── crypto.rs              # Cryptographic primitives (Ed25519, JCS, SHA-256)
│   │   └── errors.rs              # Domain error types (thiserror-based)
│   │
│   ├── state/                     # State management (Redis, caching)
│   │   ├── mod.rs                 # Module declarations
│   │   ├── redis_store.rs         # Redis operations (connection pool, atomic ops)
│   │   ├── policy_cache.rs        # In-memory policy cache (Moka, TTL-based)
│   │   └── session_history.rs     # Session history tracking (optional, if separated)
│   │
│   ├── engine/                    # Policy evaluation engine
│   │   ├── mod.rs                 # Module declarations
│   │   ├── evaluator.rs           # Static/dynamic rule evaluation (O(1) to O(n))
│   │   └── pattern_matcher.rs     # Pattern matching (sequence, logic)
│   │
│   ├── loader/                     # Configuration loading
│   │   ├── mod.rs                 # Module declarations
│   │   ├── policy_loader.rs       # YAML policy deserialization (serde_yaml)
│   │   └── tool_registry.rs      # Tool registry loading (security classes)
│   │
│   ├── auth/                       # Authentication & authorization
│   │   ├── mod.rs                 # Module declarations
│   │   ├── api_key.rs             # API key hashing, validation (SHA-256)
│   │   ├── customer_store.rs      # Database-backed customer storage (PostgreSQL)
│   │   ├── policy_store.rs        # Database-backed policy storage (JSONB)
│   │   ├── auth_middleware.rs     # Axum authentication middleware
│   │   └── audit_logger.rs        # Security event logging
│   │
│   ├── api/                       # Axum web server layer
│   │   ├── mod.rs                 # Module declarations
│   │   ├── handlers.rs            # Request handlers (proxy_execute, health, metrics)
│   │   ├── middleware.rs         # Middleware stack (auth, rate limit, tracing)
│   │   └── responses.rs           # Response types, error formatting
│   │
│   └── proxy/                     # HTTP client for MCP proxying
│       ├── mod.rs                 # Module declarations
│       └── client.rs              # Reqwest client (connection pooling, JSON-RPC 2.0)
│
├── tests/                         # Test suite
│   ├── integration/               # Integration tests (end-to-end flows)
│   │   ├── test_policy_evaluation.rs    # Policy enforcement tests
│   │   ├── test_taint_tracking.rs        # State persistence tests
│   │   ├── test_pattern_matching.rs      # Pattern detection tests
│   │   └── test_mcp_proxy.rs            # MCP protocol compliance tests
│   │
│   └── unit/                      # Unit tests (isolated components)
│       ├── test_crypto.rs        # Cryptographic operation tests
│       └── test_evaluator.rs     # Policy evaluator tests
│
└── benches/                       # Performance benchmarks
    └── crypto_bench.rs            # Cryptographic operation benchmarks
```

---

## Implementation Roadmap

### Phase 0: Foundation & Setup

**Objective:** Establish development environment and project scaffolding.

**Tasks:**

- [ ] Verify Rust toolchain (1.75+)
- [ ] Set up CI/CD pipeline (GitHub Actions / GitLab CI)
- [ ] Configure development tools (rustfmt, clippy, rust-analyzer)
- [ ] Set up pre-commit hooks (formatting, linting)
- [ ] Create development documentation (CONTRIBUTING.md)

**Acceptance Criteria:**

- `cargo build` succeeds
- `cargo test` runs (all tests pass, even if empty)
- `cargo clippy` passes with no warnings
- CI pipeline green

---

### Phase 1: Core Domain Models

**Objective:** Implement pure Rust domain logic with zero I/O dependencies.

#### 1.1 Domain Models (`src/core/models.rs`)

**Implementation Tasks:**

- [ ] Define `SessionId` newtype wrapper around `Uuid`
- [ ] Implement `ToolCall` struct with `tool_name` and `args`
- [ ] Define `ProxyRequest` with serde derives
- [ ] Implement `PolicyDefinition` with static and taint rules
- [ ] Define `Decision` enum (Allowed, Denied, AllowedWithSideEffects)
- [ ] Implement `PolicyContext` struct for evaluation
- [ ] Define `HistoryEntry` struct for session tracking

**Technical Considerations:**

- Use `#[derive(Serialize, Deserialize)]` for JSON/YAML compatibility
- Implement `FromStr` for `SessionId` for parsing
- Use `Cow<str>` where possible to avoid allocations (future optimization)
- Ensure all types are `Send + Sync` for async usage

**Testing:**

- [ ] Unit tests for `SessionId` parsing and validation
- [ ] Property-based tests for `ToolCall` serialization round-trips
- [ ] Table-driven tests for `Decision` enum variants

**Acceptance Criteria:**

- All models compile without warnings
- Serialization/deserialization round-trips work correctly
- Complete test coverage for domain models

#### 1.2 Cryptographic Primitives (`src/core/crypto.rs`)

**Implementation Tasks:**

- [ ] Implement `CryptoSigner` struct with `Secret<SigningKey>`
- [ ] Load Ed25519 private key from PEM file
- [ ] Implement `mint_token()` method (JWT with EdDSA)
- [ ] Implement `canonicalize()` using `serde_jcs` (RFC 8785)
- [ ] Implement `hash_params()` using SHA-256
- [ ] Add error handling for all cryptographic operations

**Technical Considerations:**

- Use `secrecy::Secret<T>` for private key storage
- Ensure constant-time operations (no secret-dependent branches)
- Validate token expiry (5 seconds)
- Include `jti` (nonce) in token for replay protection
- Use `hex` crate for hash encoding

**Security Considerations:**

- Never log private keys (use `secrecy` wrapper)
- Validate all inputs before cryptographic operations
- Use cryptographically secure random number generator for `jti`

**Testing:**

- [ ] Unit tests for token minting and verification
- [ ] Property-based tests for canonicalization (deterministic output)
- [ ] Fuzz tests for parameter hashing
- [ ] Benchmarks for cryptographic operations (<100μs target)

**Acceptance Criteria:**

- Token minting produces valid JWT tokens
- Canonicalization is deterministic (same input = same output)
- Parameter hashing matches Python implementation
- All cryptographic operations are constant-time where applicable

#### 1.3 Error Types (`src/core/errors.rs`)

**Implementation Tasks:**

- [ ] Define `InterceptorError` enum with `thiserror`
- [ ] Implement error conversion from `CryptoError`, `RedisError`, etc.
- [ ] Define `CryptoError` enum for cryptographic failures
- [ ] Implement `Display` trait for user-friendly error messages
- [ ] Ensure no stack traces in error messages

**Technical Considerations:**

- Use `#[from]` attribute for automatic error conversion
- Generic error messages for authentication failures
- Detailed error messages for internal errors (logged, not exposed)

**Testing:**

- [ ] Unit tests for error conversion
- [ ] Verify error messages don't contain sensitive information

**Acceptance Criteria:**

- All error types compile and implement `std::error::Error`
- Error messages are user-friendly and secure
- Error conversion works correctly

---

### Phase 2: State Management

**Objective:** Implement Redis-backed state management with connection pooling and caching.

#### 2.1 Redis Store (`src/state/redis_store.rs`)

**Implementation Tasks:**

- [ ] Set up `bb8-redis` connection pool
- [ ] Implement `get_taints()` for session taint retrieval
- [ ] Implement `add_taint()` with TTL
- [ ] Implement `remove_taint()` for taint removal
- [ ] Implement `add_history_entry()` with LRU trimming (last 1000)
- [ ] Implement `get_history()` for session history retrieval
- [ ] Add atomic operations using Redis transactions or Lua scripts

**Technical Considerations:**

- Connection pool size: Configurable (default: 20)
- Connection timeout: Configurable (default: 2s, fail fast)
- Use async Redis operations (`tokio-comp` feature)
- Implement retry logic for transient failures
- Use Redis SET for taints (O(1) membership check)
- Use Redis LIST for history (O(1) append, O(n) retrieval)

**Performance Targets:**

- Taint lookup: <1ms p99
- History append: <2ms p99
- Atomic operations: <5ms p99

**Testing:**

- [ ] Integration tests with embedded Redis
- [ ] Test connection pool exhaustion handling
- [ ] Test atomic operations (concurrent requests)
- [ ] Test TTL expiration

**Acceptance Criteria:**

- All Redis operations work correctly
- Connection pooling handles concurrent requests
- Atomic operations prevent race conditions
- Performance targets met

#### 2.2 Policy Cache (`src/state/policy_cache.rs`)

**Implementation Tasks:**

- [ ] Set up Moka cache with TTL
- [ ] Implement cache lookup by API key
- [ ] Implement cache insertion with policy
- [ ] Add cache statistics (hit rate, miss rate)
- [ ] Implement cache invalidation (manual, future: automatic)

**Technical Considerations:**

- Cache key: SHA-256 hash of API key (prevent timing attacks)
- Cache value: `Arc<PolicyDefinition>` (shared ownership)
- Max capacity: Configurable (default: 1000 policies, LRU eviction)
- Use `moka::future::Cache` for async operations

**Testing:**

- [ ] Unit tests for cache hit/miss scenarios
- [ ] Test TTL expiration
- [ ] Test LRU eviction
- [ ] Benchmarks for cache operations (<100ns target)

**Acceptance Criteria:**

- Cache operations are thread-safe
- TTL expiration works correctly
- LRU eviction works when capacity exceeded
- High cache hit rate under normal load

#### 2.3 Session History (Optional, if separated)

**Implementation Tasks:**

- [ ] Move history operations to separate module if needed
- [ ] Implement history query optimization (indexing, future)

---

### Phase 3: Policy Engine

**Objective:** Implement deterministic policy evaluation engine with pattern matching.

#### 3.1 Policy Evaluator (`src/engine/evaluator.rs`)

**Implementation Tasks:**

- [ ] Implement static rule evaluation (O(1) HashMap lookup)
- [ ] Implement dynamic taint rule evaluation (O(n) iteration)
- [ ] Implement tool matching logic (by name or class)
- [ ] Aggregate side effects (taints to add/remove)
- [ ] Return `Decision` enum with appropriate variant
- [ ] Add early termination on DENY decisions

**Technical Considerations:**

- Use `HashSet` for efficient taint intersection
- Early return on first DENY to optimize performance
- Collect side effects during evaluation (single pass)
- Use pattern matching for decision aggregation

**Performance Targets:**

- Static rule evaluation: <100ns
- Dynamic rule evaluation: <1ms (for typical 5-10 rules)
- Total evaluation: <1ms p99

**Testing:**

- [ ] Unit tests for static rule evaluation
- [ ] Unit tests for dynamic taint rule evaluation
- [ ] Table-driven tests for various policy configurations
- [ ] Property-based tests for decision correctness

**Acceptance Criteria:**

- All policy rules evaluate correctly
- Performance targets met
- Early termination works correctly
- Side effects collected accurately

#### 3.2 Pattern Matcher (`src/engine/pattern_matcher.rs`)

**Implementation Tasks:**

- [ ] Implement sequence pattern matching (sliding window)
- [ ] Implement logic pattern matching (recursive descent)
- [ ] Support AND, OR, NOT operators
- [ ] Support `max_distance` constraint for sequences
- [ ] Optimize pattern matching (memoization, future)

**Technical Considerations:**

- Use sliding window algorithm for sequence detection
- Recursive descent parser for logic expressions
- Memoize history queries (future optimization)
- Early termination on pattern match

**Testing:**

- [ ] Unit tests for sequence pattern matching
- [ ] Unit tests for logic pattern matching
- [ ] Test edge cases (empty history, single entry)
- [ ] Test `max_distance` constraint

**Acceptance Criteria:**

- All pattern types match correctly
- Performance acceptable (<5ms for complex patterns)
- Edge cases handled correctly

---

### Phase 4: Authentication & Authorization

**Objective:** Implement production-ready API key management with database storage.

#### 4.1 API Key Hashing (`src/auth/api_key.rs`)

**Implementation Tasks:**

- [ ] Implement `ApiKeyHash` struct with SHA-256 hashing
- [ ] Implement `ApiKey` wrapper with `Secret<String>`
- [ ] Implement constant-time comparison using `subtle::ConstantTimeEq`
- [ ] Add unit tests for hashing determinism
- [ ] Benchmark hashing performance (<10μs target)

**Technical Considerations:**

- Use `sha2` crate for SHA-256 hashing
- Use `subtle` crate for constant-time operations
- Use `secrecy` crate for memory protection
- Hex encoding for database storage (64 characters)

**Security Considerations:**

- Never log API keys (use `secrecy` wrapper)
- Constant-time hashing prevents timing attacks
- Hash immediately upon receipt, never store plaintext

**Acceptance Criteria:**

- API key hashing is deterministic (same key = same hash)
- Constant-time comparison prevents timing attacks
- Performance targets met (<10μs for hashing)

#### 4.2 Customer Store (`src/auth/customer_store.rs`)

**Implementation Tasks:**

- [ ] Set up PostgreSQL connection pool (`sqlx`)
- [ ] Implement database schema (customers table with indexes)
- [ ] Implement `CustomerStore` with Moka cache
- [ ] Implement `lookup_customer()` with cache-first strategy
- [ ] Implement cache invalidation for key rotation
- [ ] Add background task for `last_used_at` updates
- [ ] Implement batch lookup (future optimization)

**Technical Considerations:**

- Connection pool size: Configurable (default: 20)
- Cache TTL: Configurable (default: 5 minutes)
- Cache capacity: Configurable (default: 10k customers)
- Use `sqlx` with compile-time query checking
- Indexed hash lookup for O(1) database queries

**Database Schema:**

- `api_key_hash` VARCHAR(64) UNIQUE with partial index (`revoked_at IS NULL`)
- Covering index for common queries
- Soft delete via `revoked_at` timestamp

**Performance Targets:**

- Cache hit: <100ns
- Cache miss: <5ms (database query)
- High cache hit rate under normal load

**Testing:**

- [ ] Integration tests with PostgreSQL
- [ ] Test cache hit/miss scenarios
- [ ] Test cache invalidation
- [ ] Test concurrent lookups
- [ ] Test key rotation flow

**Acceptance Criteria:**

- Customer lookup works correctly
- Cache improves performance significantly
- Database queries are optimized with indexes
- Key rotation invalidates cache correctly

#### 4.3 Policy Store (`src/auth/policy_store.rs`)

**Implementation Tasks:**

- [ ] Implement database schema (policies table with JSONB)
- [ ] Implement `PolicyStore` with Moka cache
- [ ] Implement `load_policy()` with cache-first strategy
- [ ] Implement JSONB deserialization for policies
- [ ] Implement cache invalidation on policy updates
- [ ] Add policy update watching (future: PostgreSQL LISTEN/NOTIFY)

**Technical Considerations:**

- JSONB storage for flexible policy structure
- Cache TTL: Configurable (default: 1 hour)
- Cache capacity: Configurable (default: 1k policies)
- Use `serde_json` for JSONB deserialization

**Testing:**

- [ ] Integration tests with PostgreSQL
- [ ] Test JSONB serialization/deserialization
- [ ] Test cache invalidation
- [ ] Test policy updates

**Acceptance Criteria:**

- Policies load correctly from database
- JSONB storage maintains policy structure
- Cache improves performance
- Policy updates invalidate cache

#### 4.4 Authentication Middleware (`src/auth/auth_middleware.rs`)

**Implementation Tasks:**

- [ ] Implement Axum middleware for authentication
- [ ] Extract API key from `X-API-Key` header
- [ ] Hash API key for lookup
- [ ] Lookup customer from store
- [ ] Load policy from store
- [ ] Attach customer and policy to request extensions
- [ ] Log authentication events (success/failure)
- [ ] Return appropriate error responses

**Technical Considerations:**

- Use Axum `extract::Request` and `extensions_mut()`
- Constant-time API key hashing
- Generic error messages (prevent user enumeration)
- Fire-and-forget audit logging

**Security Considerations:**

- Fail-closed on any error
- No information disclosure in error messages
- Audit logging for security analysis
- Rate limit detection (future)

**Testing:**

- [ ] Integration tests for middleware
- [ ] Test authentication success flow
- [ ] Test authentication failure flow
- [ ] Test invalid API key handling
- [ ] Test revoked key handling

**Acceptance Criteria:**

- Authentication middleware works correctly
- Error handling is secure (no information disclosure)
- Audit logging captures all events
- Performance targets met

#### 4.5 Audit Logger (`src/auth/audit_logger.rs`)

**Implementation Tasks:**

- [ ] Implement database schema (auth_audit_log table)
- [ ] Implement `AuditLogger` struct
- [ ] Implement `log_auth_success()` method
- [ ] Implement `log_auth_failure()` method
- [ ] Extract IP address and user agent from request
- [ ] Fire-and-forget async logging
- [ ] Add rate limit detection (future)

**Technical Considerations:**

- Async logging to prevent blocking request path
- Structured logging format
- Indexed queries for security analysis
- Log retention policy (configurable)

**Testing:**

- [ ] Integration tests for audit logging
- [ ] Test log entry creation
- [ ] Test async logging doesn't block
- [ ] Test log query performance

**Acceptance Criteria:**

- All authentication events logged
- Logging doesn't impact request latency
- Logs are queryable for security analysis

---

### Phase 5: Configuration Loading

**Objective:** Implement YAML configuration loading with validation (legacy support, migration path to database).

#### 5.1 Policy Loader (`src/loader/policy_loader.rs`)

**Implementation Tasks:**

- [ ] Implement file discovery (multiple fallback paths)
- [ ] Load policies from YAML using `serde_yaml`
- [ ] Validate policy structure (required fields, enum values)
- [ ] Load customer configurations (API key -> customer mapping)
- [ ] Load tool registry (tool name -> security classes)
- [ ] Implement singleton pattern (shared across requests)

**Technical Considerations:**

- File discovery: env var > project root > Docker path
- Use `serde_yaml` for deserialization
- Validate all required fields present
- Validate enum values (ALLOW/DENY, action types)
- Validate URLs for MCP upstream

**Error Handling:**

- Detailed error messages with file path and line number
- Fail fast on invalid configuration
- Log configuration loading errors

**Testing:**

- [ ] Unit tests for YAML deserialization
- [ ] Test file discovery fallback paths
- [ ] Test validation errors
- [ ] Test invalid configuration handling

**Acceptance Criteria:**

- Policies load correctly from YAML
- Validation catches invalid configurations
- File discovery works in all environments
- Error messages are helpful

#### 4.2 Tool Registry Loader (`src/loader/tool_registry.rs`)

**Implementation Tasks:**

- [ ] Load tool registry from YAML
- [ ] Map tool names to security classes
- [ ] Validate tool registry structure
- [ ] Implement lookup by tool name

**Testing:**

- [ ] Unit tests for tool registry loading
- [ ] Test lookup by tool name
- [ ] Test missing tool handling

**Acceptance Criteria:**

- Tool registry loads correctly
- Lookup works efficiently
- Missing tools handled gracefully

**Migration Strategy:**

- Phase 1: Dual mode (Database + YAML fallback)
- Phase 2: Database migration script for YAML import
- Phase 3: Remove YAML support, database-only

---

### Phase 6: API Layer

**Objective:** Implement Axum web server with middleware stack and request handlers.

#### 5.1 Request Handlers (`src/api/handlers.rs`)

**Implementation Tasks:**

- [ ] Implement `proxy_execute_handler()` (main endpoint)
- [ ] Extract API key from `X-API-Key` header (via auth middleware)
- [ ] Load customer and policy from request extensions (set by auth middleware)
- [ ] Fetch session state from Redis
- [ ] Evaluate policy using engine
- [ ] Mint JWT token using crypto signer
- [ ] Forward request to MCP server via proxy client
- [ ] Update state asynchronously (fire-and-forget)
- [ ] Return JSON response
- [ ] Implement health check handler (`/health`)
- [ ] Implement metrics handler (`/metrics`)

**Technical Considerations:**

- Use Axum extractors (`State`, `Json`)
- Customer and policy extracted from request extensions (set by auth middleware)
- Async state updates using `tokio::spawn`
- Proper error handling with HTTP status codes
- Generic error messages to clients

**Error Handling:**

- Map domain errors to HTTP status codes
- 401 for authentication failures
- 403 for authorization failures
- 500 for internal errors
- 502 for MCP proxy errors

**Testing:**

- [ ] Integration tests for request handling
- [ ] Test error handling (invalid API key, policy violation)
- [ ] Test async state updates
- [ ] Test health check endpoint
- [ ] Test metrics endpoint

**Acceptance Criteria:**

- All endpoints work correctly
- Error handling is secure (no information disclosure)
- Performance targets met (<60ms p99)
- Async state updates work correctly

#### 5.2 Middleware Stack (`src/api/middleware.rs`)

**Implementation Tasks:**

- [ ] Implement rate limiting middleware (`tower_governor`)
- [ ] Configure request timeout middleware (`tower::timeout`)
- [ ] Configure body size limit middleware (`tower::limit`)
- [ ] Set up tracing middleware (`tower-http::trace`)
- [ ] Configure CORS middleware (if needed)
- [ ] Set up panic recovery middleware

**Technical Considerations:**

- Rate limiting: Configurable per customer
- Global timeout: Configurable (default: 30s)
- Body size limit: 2MB
- Use `tower::ServiceBuilder` for middleware composition
- Configure tracing with JSON output

**Testing:**

- [ ] Test rate limiting (exceed limits)
- [ ] Test request timeout (slow requests)
- [ ] Test body size limit (large requests)
- [ ] Test tracing (request IDs, structured logs)

**Acceptance Criteria:**

- All middleware works correctly
- Rate limiting prevents abuse
- Timeouts prevent resource exhaustion
- Tracing provides useful observability

#### 5.3 Response Types (`src/api/responses.rs`)

**Implementation Tasks:**

- [ ] Define response types for all endpoints
- [ ] Implement error response formatting
- [ ] Ensure consistent JSON structure

---

### Phase 7: MCP Proxy Client

**Objective:** Implement HTTP client for forwarding requests to MCP servers.

#### 6.1 Proxy Client (`src/proxy/client.rs`)

**Implementation Tasks:**

- [ ] Set up Reqwest client with connection pooling
- [ ] Configure connection pool (configurable size, idle timeout)
- [ ] Enable TCP_NODELAY for low latency
- [ ] Implement `forward_request()` method
- [ ] Construct JSON-RPC 2.0 request format
- [ ] Add Bearer token authentication
- [ ] Handle JSON-RPC 2.0 response format
- [ ] Map JSON-RPC errors to domain errors
- [ ] Implement request timeout (configurable)
- [ ] Add retry logic (if needed, future)

**Technical Considerations:**

- Reuse client across all requests (singleton)
- Connection pooling for performance
- Proper JSON-RPC 2.0 protocol compliance
- Error code mapping (JSON-RPC -> HTTP)

**Testing:**

- [ ] Integration tests with mock MCP server
- [ ] Test JSON-RPC 2.0 protocol compliance
- [ ] Test error handling
- [ ] Test connection pooling
- [ ] Test timeout handling

**Acceptance Criteria:**

- MCP proxy works correctly
- JSON-RPC 2.0 protocol compliant
- Connection pooling improves performance
- Error handling is robust

---

### Phase 8: Application Bootstrap

**Objective:** Wire all components together and create the main application.

#### 7.1 Configuration (`src/config.rs`)

**Implementation Tasks:**

- [ ] Load configuration from environment variables
- [ ] Set up default values
- [ ] Validate configuration
- [ ] Provide configuration struct

**Technical Considerations:**

- Use `config` crate or `dotenv` for env var loading
- Validate all required configuration present
- Provide helpful error messages for missing config

#### 7.2 Main Application (`src/main.rs`)

**Implementation Tasks:**

- [ ] Initialize tracing subscriber (JSON, structured logs)
- [ ] Load configuration
- [ ] Initialize PostgreSQL connection pool
- [ ] Initialize Redis store
- [ ] Initialize customer store (database-backed)
- [ ] Initialize policy store (database-backed)
- [ ] Initialize policy loader (YAML fallback, migration)
- [ ] Initialize crypto signer
- [ ] Initialize policy evaluator
- [ ] Initialize proxy client
- [ ] Create application state (`AppState`)
- [ ] Build Axum router with middleware (auth middleware first)
- [ ] Set up health check endpoint (include database connectivity check)
- [ ] Set up metrics endpoint
- [ ] Start HTTP server
- [ ] Implement graceful shutdown (SIGTERM/SIGINT)

**Technical Considerations:**

- Use `tracing_subscriber` for structured logging
- Initialize all components before starting server
- Use `Arc` for shared state
- Implement graceful shutdown with `tokio::signal`

**Testing:**

- [ ] Integration test for server startup
- [ ] Test graceful shutdown
- [ ] Test configuration loading

**Acceptance Criteria:**

- Server starts successfully
- All endpoints accessible
- Graceful shutdown works
- Configuration loads correctly

---

### Phase 9: Testing & Quality Assurance

**Objective:** Comprehensive test coverage and quality assurance.

#### 8.1 Unit Tests

**Tasks:**

- [ ] Complete coverage for crypto operations
- [ ] All decision paths covered for policy evaluator
- [ ] All pattern types covered for pattern matcher
- [ ] Add property-based tests for critical paths
- [ ] Add fuzz tests for JSON deserialization

#### 8.2 Integration Tests

**Tasks:**

- [ ] End-to-end policy evaluation tests
- [ ] State persistence tests (Redis)
- [ ] Pattern matching tests
- [ ] MCP proxy protocol compliance tests
- [ ] Error handling tests

#### 8.3 Performance Benchmarks

**Tasks:**

- [ ] Benchmark cryptographic operations
- [ ] Benchmark policy evaluation
- [ ] Benchmark Redis operations
- [ ] Verify performance targets met

---

### Phase 10: Production Hardening

**Objective:** Prepare for production deployment.

#### 9.1 Security Audit

**Tasks:**

- [ ] Review all cryptographic operations
- [ ] Audit error handling (no information disclosure)
- [ ] Review secret management
- [ ] Audit input validation
- [ ] Review rate limiting configuration
- [ ] Security testing (penetration testing, future)

#### 9.2 Observability

**Tasks:**

- [ ] Set up Prometheus metrics
- [ ] Configure structured logging (JSON)
- [ ] Add distributed tracing (if needed)
- [ ] Set up health check endpoint
- [ ] Add metrics endpoint

#### 9.3 Documentation

**Tasks:**

- [ ] API documentation
- [ ] Configuration documentation
- [ ] Deployment guide
- [ ] Troubleshooting guide
- [ ] Architecture documentation

---

### Phase 11: Deployment & CI/CD

**Objective:** Set up deployment pipeline and Docker images.

#### 10.1 Docker Image

**Tasks:**

- [ ] Optimize Dockerfile (multi-stage build)
- [ ] Use distroless base image
- [ ] Minimize image size
- [ ] Test Docker build
- [ ] Test Docker run

#### 10.2 CI/CD Pipeline

**Tasks:**

- [ ] Set up GitHub Actions / GitLab CI
- [ ] Configure automated testing
- [ ] Configure automated linting (clippy)
- [ ] Configure automated formatting (rustfmt)
- [ ] Set up Docker image building
- [ ] Set up deployment pipeline (if applicable)

---

## Critical Path

1. Core domain models
2. State management
3. Policy engine
4. Authentication & authorization (database-backed)
5. Configuration loading (YAML, migration to DB)
6. API layer
7. Application bootstrap
8. Testing & QA
9. Production hardening
10. Deployment

**Risk Mitigation:**

- Start with core domain models (foundation)
- Implement integration tests early (catch issues early)
- Performance benchmarks throughout (not just at end)
- Security review early and often

---

## Success Criteria

### Functional Requirements

- [ ] All Python interceptor features implemented
- [ ] MCP JSON-RPC 2.0 protocol compliance
- [ ] LangChain agent compatibility (via existing SDK)
- [ ] Policy evaluation correctness (matches Python behavior)

### Non-Functional Requirements

- [ ] Performance: 10,000+ RPS per instance
- [ ] Latency: <5ms p99 for policy evaluation, <60ms p99 end-to-end
- [ ] Memory: <100MB baseline, <500MB under load
- [ ] CPU: Low utilization at 1k RPS, moderate at 10k RPS
- [ ] Test coverage: High overall, complete for critical paths

### Security Requirements

- [ ] No information disclosure in error messages
- [ ] Constant-time API key comparison (SHA-256 hash-based)
- [ ] Database-backed key storage (no plaintext keys)
- [ ] Secure secret management (`secrecy` crate)
- [ ] Fail-closed security model
- [ ] Rate limiting prevents abuse
- [ ] Audit logging for all authentication events
- [ ] Key rotation support with soft delete

### Operational Requirements

- [ ] Structured logging (JSON)
- [ ] Prometheus metrics
- [ ] Health check endpoint (database connectivity)
- [ ] Graceful shutdown
- [ ] Docker image minimized
- [ ] Database migrations (sqlx migrate)

---

## Post-Implementation Optimizations (Future)

1. **Zero-Copy Deserialization:** Use `Cow<str>` and reference borrowing
2. **Rule Indexing:** Index rules by tool name/class for faster lookup
3. **Pattern Matching Optimization:** Finite state machines for sequence patterns
4. **Connection Pool Tuning:** Adaptive pool sizing based on load
5. **Cache Warming:** Pre-load policies on startup
6. **Distributed Tracing:** OpenTelemetry integration
7. **Metrics Aggregation:** Prometheus remote write
8. **Policy Hot Reloading:** PostgreSQL LISTEN/NOTIFY for real-time updates
9. **Database Read Replicas:** Scale read operations across replicas
10. **Key Rotation Automation:** Automated key rotation with grace period

---

## Key Success Factors

- Start with core domain models (foundation)
- Test early and often
- Benchmark performance throughout
- Security review at each phase
- Document as you go
