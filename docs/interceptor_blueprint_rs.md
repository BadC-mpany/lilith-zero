This blueprint describes the implementation of the **Sentinel Interceptor (v1.0)** using **Rust**. This architecture prioritizes memory safety, zero-cost abstractions, and high-concurrency throughput (10k+ RPS) to ensure the security layer does not become a latency bottleneck.

### I. Architectural Philosophy: The "Tower" Pattern

We will utilize the **Tower** ecosystem (the foundation of the Rust async web stack). The application is modeled not just as a server, but as a stack of functional middleware layers.

**The Stack:**

1.  **Transport Layer:** `Hyper` (HTTP/1.1 & HTTP/2).
2.  **Protective Middleware:** Rate limiting, Timeout, Panic Recovery.
3.  **Observability Middleware:** Tracing ID injection, Metrics scraping.
4.  **Application Logic (Axum Handlers):** The core Policy Engine.
5.  **Client Layer:** `Reqwest` (Connection pooled proxy client).

---

### II. Core Dependencies (The "Weapons of Choice")

To ensure production readiness, we select crates that are widely audited and used in high-scale environments (AWS, Cloudflare).

- **Runtime:** `tokio` (Multi-threaded, work-stealing scheduler).
- **Web Framework:** `axum` (Ergonomic, modular, extractor-based).
- **Serialization:** `serde`, `serde_json` (High performance).
- **Canonicalization:** `serde_jcs` (Strict RFC 8785 compliance).
- **Cryptography:** `ed25519-dalek` (Signature), `secrecy` (Memory protection).
- **Data/Cache:** `redis` (Async driver), `bb8` (Connection pooling), `moka` (High-performance in-memory caching).
- **Observability:** `tracing`, `tracing-subscriber` (Structured logging).
- **Error Handling:** `thiserror` (Library errors), `anyhow` (App errors).

---

### III. Module-by-Module Technical Blueprint

#### Module 1: `sentinel_core` (The Domain Kernel)

This module is pure Rust. It has no network I/O dependencies. It defines the "Truth" of the system.

- **`models.rs`**: Defines the rigorous structs.
  - `SessionId`: Newtype wrapper around UUID.
  - `ToolCall`: Struct containing `tool_name` (String) and `args` (serde_json::Value).
  - `Policy`: Enum-based definition of Allow/Deny/Taint rules. Enums make invalid policy states unrepresentable.
- **`crypto.rs`**:
  - **Canonicalizer**: Implements the logic to take `serde_json::Value` and produce a deterministic `Vec<u8>` using `serde_jcs`. This is the most critical security function to prevent TOCTOU.
  - **Signer**: Wraps `ed25519_dalek::SigningKey`. Implements `mint_token(claims) -> Result<String>`.
- **`errors.rs`**: Defines domain errors (`PolicyViolation`, `TaintBlock`, `SignatureFailure`) ensuring we don't leak internal stack traces to the client.

#### Module 2: `sentinel_state` (The Ledger)

Handles all persistence. It uses a "Two-Level Cache" strategy to ensure sub-millisecond policy lookups.

- **`redis_store.rs`**:
  - Manages the `bb8` connection pool to Redis.
  - Implements `Atomic Tainting`: Uses Redis transactions (`MULTI/EXEC`) or Lua scripts to ensure that reading taints and updating them happens safely.
- **`policy_cache.rs`**:
  - Uses `moka` (a high-performance concurrent cache) to store Customer Policies indexed by API Key.
  - **TTL Strategy**: Policies are cached for 60 seconds. This prevents hitting the SQL/Redis DB on every single request, allowing the engine to run at memory speed.

#### Module 3: `sentinel_engine` (The Brain)

The Deterministic State Machine that enforces rules.

- **`evaluator.rs`**:
  - **Input:** `Context` (Taints), `Policy` (Rules), `Intent` (Tool Call).
  - **Logic:**
    1.  **Static Check:** O(1) lookup in the Policy AllowList.
    2.  **Dynamic Check:** Set intersection between `Context.Taints` and `Rule.ForbiddenTaints`.
  - **Output:** `Decision` Enum (`Allowed`, `Denied`, `AllowedWithSideEffects`).

#### Module 4: `sentinel_api` (The Interface)

The `Axum` web server layer.

- **`middleware.rs`**:
  - **`AuthMiddleware`**: Extracts `X-API-Key`. Hashes it (SHA-256) to prevent timing attacks during comparison. Looks up the Customer ID.
  - **`RateLimitMiddleware`**: Uses `tower_governor` (Leaky Bucket algorithm) keyed by Customer ID to prevent SaaS abuse.
- **`handlers.rs`**:
  - **`proxy_handler`**: The main entry point.
    1.  Extracts Json Body.
    2.  Calls `sentinel_state` to get Taints.
    3.  Calls `sentinel_engine` to evaluate.
    4.  Calls `sentinel_core` to mint JWT.
    5.  Calls `sentinel_proxy` to forward request.
    6.  Background Task (`tokio::spawn`): Updates Redis with new Taints (fire-and-forget to lower latency).

#### Module 5: `sentinel_proxy` (The Tunnel)

The HTTP Client wrapper.

- **`client.rs`**:
  - Initializes a `reqwest::Client` with `pool_idle_timeout` and `tcp_nodelay` enabled.
  - This client is reused across the entire application lifetime to maintain persistent TCP connections (Keep-Alive) to the upstream MCP servers, eliminating the TLS handshake overhead on every request.

---

### IV. The Data Flow (The "Hot Path")

1.  **Ingress:** Request hits `Axum`. `tower-http` generates a `TraceID`.
2.  **Auth:** Middleware validates API Key against `Moka` cache.
3.  **State Fetch:** Handler requests Session Taints from Redis (Async I/O).
4.  **Evaluation:** Engine runs pure logic check (Nanoseconds).
    - _If Blocked:_ Returns 403 immediately.
5.  **Binding:** Core canonicalizes Args and signs the JWT using `Ed25519` (Microseconds).
6.  **Proxying:** `Reqwest` forwards request to hidden MCP URL with `Authorization: Bearer <JWT>` (Network Latency).
7.  **Response:** Interceptor receives MCP response.
8.  **Side Effect:** Handler spawns a background Tokio task to `SADD` (Set Add) new taints to Redis.
9.  **Egress:** Response returns to Agent.

---

### V. Production Readiness & Security Hardening

#### 1. Secret Management

We use the `secrecy` crate. The Private Key is loaded into a `Secret<Vec<u8>>`. This wrapper types prevents the key from being printed in debug logs (`Debug` trait is redacted) and attempts to keep the memory unswappable.

#### 2. Denial of Service (DoS) Protection

- **Body Size Limit:** `Axum` is configured to reject request bodies > 2MB to prevent memory exhaustion attacks.
- **Timeouts:** `tower_timeout` enforces a global 30s timeout to prevent hung connections from consuming file descriptors.

#### 3. Docker & Deployment

- **Build Stage:** Uses `cargo chef` to cache dependencies, speeding up CI/CD builds.
- **Runtime Image:** Google's `distroless/cc-debian12`.
  - Contains _only_ the binary and glibc. No shell, no package manager, no python.
  - Massively reduces attack surface. If an attacker gets RCE, they have no shell to execute commands.

#### 4. Observability

- **Metrics:** Exposes `/metrics` endpoint (Prometheus format) tracking:
  - `interceptor_requests_total` (labeled by `status=allow|deny`).
  - `interceptor_latency_histogram`.
  - `redis_pool_status`.
- **Logging:** JSON structured logs via `tracing_subscriber` for ingestion into ELK/Datadog.

### VI. Why this Architecture is "Senior Level"

1.  **Zero-Copy Deserialization:** Where possible, we use `Cow<str>` and reference borrowing to avoid cloning memory strings, reducing GC pressure (even though Rust doesn't have GC, it has allocator pressure).
2.  **Infallible Canonicalization:** By relying on `serde_jcs` rather than ad-hoc sorting, we mathematically guarantee that the signature verification on the MCP side (if also using JCS) is robust.
3.  **Fail-Closed:** The architecture utilizes Rust's `?` operator. Any failure in Redis, Auth, or Signing propagates up and returns an Internal Server Error or Forbidden, never leaking access.
4.  **Async-First:** The architecture is fully non-blocking. A single generic vCPU instance can handle thousands of concurrent agent requests.

This is the architectural and repository blueprint for the **Sentinel Interceptor (v1.0)**. It is designed to be your source of truth for the implementation.

### 1\. Repository Strategy: Rust Workspace

We will use a **Cargo Workspace** architecture. This enforces strict separation of concerns, ensuring that the core cryptographic logic is isolated from the HTTP transport layer. This aids in auditability and compilation caching.

**Repository Name:** `sentinel-interceptor`

**Directory Structure:**

```text
sentinel-interceptor/
├── Cargo.toml                # Workspace definition
├── Cargo.lock
├── infra/                    # Terraform & Docker definitions
│   ├── Dockerfile            # Multi-stage build (Planner -> Builder -> Distroless)
│   └── docker-compose.yml    # Local dev stack (Redis + Sentinel + Mock MCP)
├── crates/
│   ├── sentinel_core/        # [LIB] Pure domain logic, crypto, and models. NO IO.
│   │   ├── src/
│   │   │   ├── crypto/       # Ed25519 signing & JCS Canonicalization
│   │   │   ├── policy/       # Policy structs & Rule matching logic
│   │   │   └── models.rs     # SessionID, ToolCall, Taint definitions
│   │   └── Cargo.toml
│   │
│   ├── sentinel_infra/       # [LIB] Database, Cache, and External IO adapters.
│   │   ├── src/
│   │   │   ├── redis/        # Taint ledger implementation
│   │   │   ├── secrets/      # Key loading (Vault/Env)
│   │   │   └── mcp/          # Upstream HTTP client
│   │   └── Cargo.toml
│   │
│   └── sentinel_api/         # [BIN] The Axum Application & Middleware.
│       ├── src/
│       │   ├── middleware/   # Auth, RateLimit, TraceId
│       │   ├── handlers/     # Proxy logic
│       │   ├── state.rs      # AppState (Arc wrapper)
│       │   └── main.rs       # Entrypoint
│       └── Cargo.toml
└── tests/                    # Integration tests
    └── end_to_end.rs         # Black-box testing of the full flow
```

---

### 2\. Crate Specifications & Technical Detail

#### Crate A: `sentinel_core` (The Domain Kernel)

**Role:** Defines the mathematical and logical truth of the system.
**Constraints:** `#[no_std]` compatible where possible (for future WASM portability), zero network dependencies.

**Critical Modules:**

1.  **`crypto::canonical`**

    - **Requirement:** Must implement RFC 8785 (JSON Canonicalization Scheme).
    - **Implementation:** Wrapper around `serde_jcs`.
    - **Function:** `pub fn hash_params<T: Serialize>(args: &T) -> Result<String, CryptoError>`
    - **Security:** This guarantees that `{"a": 1, "b": 2}` and `{"b": 2, "a": 1}` produce identical Ed25519 signatures, preventing TOCTOU.

2.  **`crypto::signing`**

    - **Requirement:** Ed25519 Provider.
    - **Crate:** `ed25519-dalek`.
    - **Function:** `pub fn mint_capability(claims: Claims, key: &SigningKey) -> String`
    - **Security:** Uses `secrecy::Secret` to protect the private key in memory.

3.  **`policy::engine`**

    - **Requirement:** Deterministic evaluation of rules.
    - **Structs:**

      ```rust
      pub enum RuleAction {
          Allow,
          Deny,
          AuditOnly,
      }

      pub struct PolicyContext {
          pub taints: HashSet<String>,
          pub tool_name: String,
      }
      ```

    - **Function:** `pub fn evaluate(policy: &Policy, context: &PolicyContext) -> Decision`

#### Crate B: `sentinel_infra` (The Adapters)

**Role:** Handles dirty I/O (Redis, Network). Implements the Repository Pattern.

**Critical Modules:**

1.  **`redis::ledger`**

    - **Crate:** `redis` with `bb8` (Connection Pooling) or `deadpool-redis`.
    - **Role:** Persistence of Session Taints.
    - **Optimization:** Use Redis Pipelining for fetching Taints.
    - **Atomic Operation:** When updating taints, use `SADD` (Set Add). For the MVP, we assume eventual consistency is acceptable for Taint writes, but reads must be strongly consistent.

2.  **`mcp::upstream`**

    - **Crate:** `reqwest`.
    - **Configuration:**
      - `pool_idle_timeout(None)`: Keep connections open indefinitely to avoid TLS handshake overhead.
      - `tcp_nodelay(true)`: Disable Nagle's algorithm for lowest latency.

#### Crate C: `sentinel_api` (The Application)

**Role:** Wiring everything together into a binary.

**Critical Modules:**

1.  **`middleware::auth`**

    - **Role:** Extract `X-API-Key`.
    - **Security:** Hash the key (`sha256`) before looking it up in the cache. Never compare raw keys (timing attack mitigation).
    - **State:** Uses `moka` (high-perf concurrent cache) to store API Key Metadata to avoid hitting the DB on every request.

2.  **`handlers::proxy` (The Hot Path)**

    - **Flow:**
      1.  **Deserialize:** Parse body to `ToolRequest` (Zero-copy `Cow<str>` if possible).
      2.  **Ledger Read:** `infra::redis::get_taints(session_id)`.
      3.  **Evaluate:** `core::policy::evaluate()`. If `Deny`, return 403.
      4.  **Bind:** `core::crypto::hash_params()`.
      5.  **Sign:** `core::crypto::mint_capability()`.
      6.  **Forward:** `infra::mcp::forward(request, token)`.
      7.  **Ledger Write (Async):** `tokio::spawn(infra::redis::add_taints())`. Fire-and-forget to minimize client latency.

---

### 3\. Implementation Checklist (Order of Operations)

1.  **Core Domain (Day 1-2):**

    - Define `Policy` struct using `serde` enums.
    - Implement `hash_params` with `serde_jcs`.
    - Write unit tests asserting that JSON key reordering does not change the hash.

2.  **Infrastructure Layer (Day 3-4):**

    - Set up `bb8` Redis pool.
    - Implement `TaintLedger` trait.
    - Implement `KeyLoader` (File/Env/AWS Secrets Manager).

3.  **API Layer (Day 5-6):**

    - Setup `Axum` router.
    - Implement `AuthMiddleware`.
    - Wire up the `ProxyHandler`.

4.  **Security Hardening (Day 7):**

    - Integrate `secrecy` for key handling.
    - Set up `tower_governor` for rate limiting.
    - Configure `tracing` for structured JSON logging.

### 4\. Technical Constraints & Standards

- **Error Handling:** Use `thiserror` for library errors and `anyhow` for the binary. All errors returned to the client must be generic (e.g., "Policy Violation") to avoid leaking internal logic, while internal logs must contain full stack traces.
- **Concurrency:** Use `tokio::sync::RwLock` if shared mutable state is absolutely necessary (avoid if possible). Prefer message passing or atomic DB operations.
- **Serialization:** All JSON structs must derive `serde::Serialize` and `serde::Deserialize`.
- **Linting:** CI must pass `cargo clippy -- -D warnings` (Disallow warnings).

### 5\. Deployment Architecture (Docker)

**Base Image:** `gcr.io/distroless/cc-debian12`

- Why? Contains `glibc`, `libssl`, and CA certificates, but no shell. Even if an RCE vulnerability exists in the app, the attacker has no shell to execute commands.

**Build Process:**

1.  **Chef:** Use `cargo-chef` to cache dependencies.
2.  **Builder:** Compile `release` binary.
3.  **Runtime:** Copy binary to Distroless.

This blueprint provides the exact, tracked structure required to build the Sentinel Interceptor. Start by initializing the workspace and implementing `sentinel_core`.
