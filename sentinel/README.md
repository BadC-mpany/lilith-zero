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

src/
├── mcp/
│   ├── server.rs     # Actor coordinator
│   ├── pipeline.rs   # Async reader/writer tasks
│   ├── process.rs    # OS-level supervision
│   └── mod.rs
├── core/
│   ├── security_core.rs # Logic kernel
│   ├── taint.rs      # Type-level safety (Clean<T>)
│   ├── crypto.rs     # HMAC session logic
│   └── mod.rs
└── engine/           # Rule evaluation logic
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
customerId: customer-id
name: Policy Name
version: 1

staticRules:
  tool_name: ALLOW | DENY

taintRules:
  - tool: source_tool
    action: ADD_TAINT
    tag: TAG
    
  - tool: sink_tool
    action: CHECK_TAINT
    forbiddenTags: [TAG]
    error: "Error message"

resourceRules:
  - uriPattern: "file:///allowed/*"
    action: ALLOW
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
