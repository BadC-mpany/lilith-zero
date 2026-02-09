# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/peti12352/lilith-zero/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/peti12352/lilith-zero/releases/tag/v0.1.0
