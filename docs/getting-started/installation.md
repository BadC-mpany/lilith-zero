# Installation

To use Lilith Zero, you need two components:
1.  **The Middleware Binary** (`lilith-zero`): The Rust-based security supervisor.
2.  **The Python SDK** (`lilith-zero-sdk`): The client library for your agents.

## Prerequisites

-   **Rust Toolchain**: [Install Rust](https://rustup.rs/) (1.75+)
-   **Python**: Python 3.10 or higher.
-   **uv** (Optional but recommended): High-performance Python package manager.

## 1. Installing the Middleware

You can install the middleware automatically via the SDK, or manually from source/releases.

=== "Option 1: Automatic (Easiest)"

    The Python SDK includes an installer that attempts to automatically download the correct binary for your system if it's not found.

    ```bash title="Terminal"
    pip install lilith-zero
    # The first time you run it, it will prompt to download the binary.
    ```

=== "Option 2: Pre-built Binaries"

    Check the [GitHub Releases](https://github.com/BadC-mpany/lilith-zero/releases) page for pre-compiled binaries for Windows, macOS, and Linux.

=== "Option 3: From Source (Recommended for Dev)"

    Clone the repository and install via cargo:

    ```bash title="Terminal"
    git clone https://github.com/BadC-mpany/lilith-zero.git
    cd lilith-zero
    cargo install --path lilith-zero
    ```

    Verify the installation:

    ```bash title="Terminal"
    lilith-zero --version
    ```

    ```text title="Output"
    lilith-zero 0.1.2
    ```

## 2. Installing the Python SDK

The SDK is available on PyPI.

```bash title="Terminal"
pip install lilith-zero
```

Or using `uv`:

```bash title="Terminal"
uv pip install lilith-zero

# Or using uv project management
uv add lilith-zero
```

## System Requirements

| OS | Supported | Isolation Mechanism |
| :--- | :--- | :--- |
| **Windows** | :material-check-bold:{ .lg } Yes | Job Objects, Restricted Tokens |
| **macOS** | :material-check-bold:{ .lg } Yes | Re-Exec Supervisor, `kqueue` |
| **Linux** | :material-check-bold:{ .lg } Yes | `PR_SET_PDEATHSIG` |
