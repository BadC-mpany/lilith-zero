# Contributing to lilith-zero

Thank you for your interest in contributing to lilith-zero! This document provides guidelines and information for contributors.

## Code of Conduct

Please be respectful and constructive in all interactions. We are committed to providing a welcoming environment for everyone.

## Getting Started

### Prerequisites

Please refer to our **[Development Guide](docs/development.md)** for detailed, cross-platform setup instructions (Linux, macOS, Windows).

We strictly enforce the use of:
- **Rust Toolchain**: Managed via `rustup`.
- **Python Environment**: Managed via `uv`.

Ensure your environment is correctly configured before proceeding.

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - Steps to reproduce
   - Expected vs actual behavior
   - OS and version information
   - Relevant logs or error messages

### Suggesting Features

1. Check existing feature requests
2. Describe the use case
3. Explain how it benefits users
4. Consider backward compatibility

### Submitting Code

1. **Fork** the repository
2. **Create a branch** for your feature: `git checkout -b feature/my-feature`
3. **Make changes** following our style guidelines
4. **Write tests** for new functionality
5. **Run tests** to ensure nothing is broken
6. **Commit** with clear messages
7. **Push** to your fork
8. **Open a Pull Request**

## Style Guidelines

### Rust

- Follow standard Rust formatting (`cargo fmt`)
- Pass all clippy lints: `cargo clippy -- -D warnings`
- Document public APIs with `///` comments
- Use descriptive variable names
- Handle errors explicitly (avoid `unwrap()` in library code)

### Python

- Follow PEP 8
- Use type annotations
- Format with ruff: `ruff format lilith_zero`
- Lint with ruff: `ruff check lilith_zero`
- Avoid mutable default arguments

### Commit Messages

Use conventional commits format:

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
- `feat(sdk): add LangChain tool conversion`
- `fix(interceptor): handle empty tool arguments`
- `docs: update installation instructions`

## Testing

### Running Tests

Detailed testing commands are available in [docs/development.md](docs/development.md#3-build--test-workflow).

Common commands:
```bash
# Rust Tests
cargo test

# Python Tests
pytest
```

### Writing Tests

- Unit tests for isolated functions
- Integration tests for end-to-end flows
- Test both success and error paths
- Use meaningful test names

## Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure CI passes
4. Request review from maintainers
5. Address review feedback
6. Squash commits if requested

## Release Process

Releases are managed by maintainers:

1. Update version in `Cargo.toml` and `pyproject.toml`
2. Update `CHANGELOG.md`
3. Create a Git tag
4. Push to trigger release workflow

## Questions?

- Open a discussion on GitHub
- Check existing documentation in `/docs`

Thank you for contributing!
