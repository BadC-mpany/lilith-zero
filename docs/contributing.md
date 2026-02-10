# Contributing

Thank you for your interest in contributing to **Lilith Zero**! We welcome patches, bug reports, and feature requests.

## Development Setup

To work on Lilith Zero, you need a development environment with both Rust and Python.

### 1. Rust Environment

We use standard `cargo` workflows.

```bash
# Build the middleware
cargo build
```

### 2. Python Environment (SDK)

We use `uv` for Python dependency management.

```bash
# Install dependencies
uv pip install -e "sdk[dev]"
```

### 3. Running Tests

We have a rigorous test suite.

```bash
# Run Rust Unit Tests
cargo test

# Run Python SDK Tests
uv run pytest sdk/tests/
```

## Documentation

The documentation (this site) is built with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/).

To run the documentation server locally:

```bash
# Install docs dependencies
uv pip install -r docs/requirements.txt

# Run the server
mkdocs serve
```

The site will be available at `http://127.0.0.1:8000`.

## Coding Standards

-   **Rust**: Run `cargo fmt` and `cargo clippy` before submitting.
-   **Python**: We use `ruff` for linting and formatting.
