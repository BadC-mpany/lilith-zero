# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.6] - 2026-05-04

### Fixed
- **Copilot Studio Hardening:** Resolved a security policy mismatch where custom tools (e.g., 'Send-an-Email') were incorrectly blocked.
  - Updated `extract_tools.py` to robustly derive precise PVA Tool IDs by extracting publisher prefixes and slugifying display names.
  - Hardened the Rust webhook runtime to use the unique `toolDefinition.id` as the primary security identifier, aligning with the actual identifiers received in runtime payloads.
  - Updated `copilot_studio.rs` tests to verify correct tool ID mapping.

## [0.2.5] - 2026-04-28

### Added
- **Formal Verification:** Migrated policy engine to use the **Cedar Policy Engine**. All policies are now evaluated using formally verified logic.
- **Native Cedar Support:** Direct support for `.cedar` policy files in `run` and `hook` modes.
- **YAML-to-Cedar Compiler:** Legacy YAML policies are now transparently compiled to Cedar `PolicySet` at runtime for unified enforcement.
- **MCP 2025.11 Readiness:** Implemented dynamic tool class registration from `tools/list` capability metadata.
- **Lethal Trifecta 2.0:** Hardened trifecta protection using Cedar forbidden rules.
- **Enhanced SDK Audit:** Python SDK now parses `[AUDIT]` streams directly from stderr, improving observability in ephemeral hook environments.

### Security
- **TOCTOU Protection:** Implemented path-mutating protection. `lilith-zero` now extracts, canonicalizes, and replaces paths in the JSON payload *before* policy evaluation and upstream forwarding.
- **Process Isolation:** Hardened Linux/macOS process management using **Process Groups** (`setpgid`). The supervisor now kills the entire child group to prevent double-fork daemonization escapes.
- **Robust Path Sanitization:** Unified `lexical_canonicalize` usage across all evaluators.
- **Panic Protection:** Added ID sanitization in the policy compiler to prevent panics on non-alphanumeric tool/resource names.

### Fixed
- Duplicated audit log parsing logic in Python SDK.
- SDK version drift (synced all components to 0.2.5).
- Red-team vulnerability in path-confusion logic.
- Taint propagation bug in Cedar ID sanitization.

## [0.1.3] - 2026-02-20
...
### Added
- Standardized Clippy lint attributes to enforce zero-tolerance for correctness/performance issues.
- `#[must_use]` and `#[non_exhaustive]` annotations to core security types for API robustness.
- `deny.toml` configuration for `cargo-deny` (license and advisory auditing).
- Automatic `cargo clippy --fix` in CI workflows.

### Fixed
- Stale version identifier in Python SDK handshake.
- Technical debt: refactored duplicated audit log parsing in `client.py`.
- Platform-agnostic path discovery in `_find_binary` using repo-root markers.
- CI Workflow consistency: fixed `uv run` usage and CodeQL matrix.

### Changed
- Refined release build profiles with full LTO and codegen optimization.
- Standardized documentation paths in skill files.

## [0.1.2] - 2026-02-18
- Initial public release
- MCP stdio proxy architecture
- HMAC-signed session IDs with constant-time validation
- Static policy enforcement (ALLOW/DENY per tool)
- Dynamic taint tracking with ADD_TAINT/CHECK_TAINT rules
- Lethal trifecta protection against data exfiltration attacks
- Resource rules with taint propagation (taintsToAdd)
- AND-logic taint checking (requiredTaints) for complex security patterns
- Spotlighting for prompt injection defense
- Process isolation via Windows Job Objects
- Process isolation via Linux PR_SET_PDEATHSIG
- Python SDK with `lilith-zero.start()` API
- LangChain tool integration
- Comprehensive demo with verification
- GitHub Actions CI workflow

### Security
- Constant-time HMAC comparison to prevent timing attacks
- Ephemeral session keys (not persisted)
- Child process binding to parent lifecycle

## [0.1.0] - 2026-01-27

### Added
- Initial release
- Core security middleware functionality
- Python SDK
- Example tools and policies

[Unreleased]: https://github.com/BadC-mpany/lilith-zero/compare/v0.2.5...HEAD
[0.2.5]: https://github.com/BadC-mpany/lilith-zero/compare/v0.1.3...v0.2.5
[0.1.3]: https://github.com/BadC-mpany/lilith-zero/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/BadC-mpany/lilith-zero/compare/v0.1.0...v0.1.2
[0.1.0]: https://github.com/BadC-mpany/lilith-zero/releases/tag/v0.1.0
