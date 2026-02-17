# Contributing

Thank you for your interest in contributing to **Lilith Zero**! We welcome patches, bug reports, and feature requests.

## Development Setup

To work on Lilith Zero, you need a development environment with both Rust and Python.

### 1. Rust Environment

We use standard `cargo` workflows.

```bash title="Terminal"
cargo build
```

### 2. Python Environment

We use a single consolidated virtual environment for the SDK, examples, and documentation.

```bash title="Terminal"
# Create the environment
uv venv

# Install all dependencies (SDK, Docs, Examples)
uv pip install -r requirements.txt
```

## Running Tests

We have a rigorous test suite.

```bash title="Terminal — Rust"
cargo test
```

```bash title="Terminal — Python"
uv run pytest sdk/tests/
```

## Documentation

The documentation is built with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/).

To run the documentation server locally:

```bash title="Terminal"
uv run mkdocs serve --config-file docs/mkdocs.yml
```

The site will be available at `http://127.0.0.1:8000`.

## Coding Standards

-   **Rust**: Run `cargo fmt` and `cargo clippy` before submitting.
-   **Python**: We use `ruff` for linting and formatting.
