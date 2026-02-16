# Installation

To use Lilith Zero, you need two components:
1.  **The Middleware Binary** (`lilith-zero`): The Rust-based security supervisor.
2.  **The Python SDK** (`lilith-zero-sdk`): The client library for your agents.

## Prerequisites

-   **Rust Toolchain**: [Install Rust](https://rustup.rs/) (1.75+)
-   **Python**: Python 3.10 or higher.
-   **uv** (Optional but recommended): High-performance Python package manager.

## 1. Installing the Middleware

You can install the middleware directly from crates.io or build it from source.

=== "From Source (Recommended)"

    Clone the repository and install via cargo:

    ```bash
    git clone https://github.com/BadC-mpany/lilith-zero.git
    cd lilith-zero
    cargo install --path lilith-zero
    ```

    Verify the installation:
    ```bash
    lilith-zero --version
    ```

=== "Pre-built Binaries"

    Check the [GitHub Releases](https://github.com/BadC-mpany/lilith-zero/releases) page for pre-compiled binaries for Windows, macOS, and Linux.

## 2. Installing the Python SDK

The SDK is available on PyPI.

```bash
pip install lilith-zero
```

Or using `uv`:

```bash
uv pip install lilith-zero

# Or using uv project management
uv add lilith-zero
```

## System Requirements

| OS | Supported | Isolation Mechanism |
| :--- | :--- | :--- |
| **Windows** | ✅ Yes | Job Objects, Restricted Tokens |
| **macOS** | ✅ Yes | Re-Exec Supervisor, `kqueue` |
| **Linux** | ✅ Yes | `PR_SET_PDEATHSIG` |
