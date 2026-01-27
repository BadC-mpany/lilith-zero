# Sentinel Interceptor

Rust MCP security middleware.

## Build

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
```

## Run

```bash
sentinel-interceptor \
  --policy policy.yaml \
  --upstream-cmd "python" \
  -- tools.py
```

## Flags

| Flag | Description |
|------|-------------|
| `--upstream-cmd` | Tool server executable |
| `--policy` | YAML policy file |
| `--` | Upstream arguments |

## Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | trace, debug, info, warn, error |

## Components

```
src/
├── main.rs           # CLI (clap)
├── constants.rs      # Centralized values
├── mcp/
│   ├── server.rs     # Request handling
│   ├── transport.rs  # JSON-RPC stdio
│   ├── process.rs    # Job Objects / PR_SET_PDEATHSIG
│   └── security.rs   # Spotlighting
├── engine/
│   └── evaluator.rs  # Policy logic
└── core/
    ├── crypto.rs     # HMAC session IDs
    ├── models.rs     # Types
    └── errors.rs     # Error types
```

## Security

### Session ID Format

```
{version}.{uuid_b64}.{hmac_b64}
    │         │           │
    │         │           └── HMAC-SHA256 signature
    │         └── UUID (16 bytes)
    └── Version (for algorithm upgrades)
```

- Ephemeral secret per process
- Constant-time comparison
- Bound to session lifecycle

### Spotlighting

```
<<<SENTINEL_DATA_START:a1b2c3d4>>>
{untrusted tool output}
<<<SENTINEL_DATA_END:a1b2c3d4>>>
```

Random ID per response prevents delimiter injection.

### Process Isolation

**Windows:**
```rust
let job = Job::create()?;
info.limit_kill_on_job_close();
job.assign_process(&child)?;
```

**Linux:**
```rust
prctl(PR_SET_PDEATHSIG, SIGKILL);
```

Parent death terminates child.

## Policy Format

```yaml
id: policy-id
name: Policy Name
version: 1

static_rules:
  tool_name: ALLOW | DENY

taint_rules:
  - tool: source_tool
    action: ADD_TAINT
    taint_tags: [TAG]
    
  - tool: sink_tool
    action: CHECK_TAINT
    forbidden_taints: [TAG]
    message: "Error message"
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async |
| `serde_json` | JSON |
| `clap` | CLI |
| `tracing` | Logging |
| `hmac` + `sha2` | Signing |
| `ring` | Random |
| `win32job` | Windows isolation |
| `libc` | Linux syscalls |

## License

[Apache-2.0](../LICENSE)
