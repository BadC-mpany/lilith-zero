# Changelog

All notable changes to Lilith Zero are documented here.

## v0.1.2 — 2026-02-16

- Fixed PyPI publishing workflow (attestation handling, metadata improvements)
- Dependency audit and security sweep
- Documentation alignment and cleanup
- Synchronized Rust core and Python SDK versions

## v0.1.1 — 2026-02-10

- Documentation overhaul and alignment with codebase
- Security suite integration (Kani formal verification in CI)
- Clippy and audit clean pass

## v0.1.0 — 2026-02-09

- Initial release
- Process supervision (Windows Job Objects, macOS Re-Exec Supervisor, Linux `PR_SET_PDEATHSIG`)
- Lethal Trifecta protection
- Policy engine with static rules, taint tracking, and resource access control
- Python SDK with async client
- Red team test suite
- Formal verification harnesses (Kani)
