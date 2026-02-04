# Sentinel Core (Rust)

High-performance, memory-safe middleware for MCP security enforcement.

## Build

```bash
cargo build --release
# Binary: ./target/release/sentinel
```

## Usage

Sentinel is typically invoked via the SDK, but can be run manually:

```bash
sentinel \
  --policy policy.yaml \
  --upstream-cmd "python" \
  -- tools.py
```

## Architecture

Sentinel uses an async Actor Model to handle concurrent I/O streams without deadlocks.

```
src/
├── mcp/
│   ├── server.rs     # Actor Coordinator
│   ├── codec.rs      # Hardened Line/LSP Framing
│   ├── process.rs    # Cross-platform Process Supervision
│   └── mod.rs
├── core/
│   ├── crypto.rs     # HMAC Session Logic
│   └── models.rs     # Policy Data Structures
└── engine/           # Policy Evaluation (Static + Taint)
```

## Security Features

1.  **Session Binding**: Ephemeral HMAC-SHA256 signatures per session.
2.  **Spotlighting**: Randomized output delimiters to prevent prompt injection.
3.  **Taint Tracking**: Information flow control for sensitive data.
4.  **Fail-Closed**: All policies deny by default.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Logging level (`info`, `debug`, `trace`) | `info` |

## License
Apache-2.0
