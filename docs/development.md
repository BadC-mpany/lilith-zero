# Development Guide

This guide provides a standardized, "Google-grade" setup for developing `lilith-zero`. We strictly enforce the use of official toolchains to ensure reproducibility across Linux, macOS, and Windows.

## 1. Prerequisites

Ensure you have the following installed before starting.

| Tool | Purpose | Recommended Install Method |
| :--- | :--- | :--- |
| **Git** | Version Control | [Official Installer](https://git-scm.com/downloads) |
| **Rust** | System Language | `rustup` (Official) |
| **Python** | SDK Language | [uv](https://github.com/astral-sh/uv) (Fastest, standardized) |
| **Make** | Task Runner | Pre-installed (Linux/macOS) or via Chocolatey/Scoop (Windows) |

---

## 2. Environment Setup

### 2.1 Clone Repository
```bash
git clone https://github.com/BadC-mpany/lilith-zero.git
cd lilith-zero
```

### 2.2 Rust Toolchain (`lilith-zero/`)
We use `rustup` to manage Rust versions.

**Linux / macOS:**
```bash
# Install rustup if missing
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install stable toolchain (default)
rustup default stable

# Install nightly toolchain (Required for Miri/Verification)
rustup toolchain install nightly
rustup component add miri --toolchain nightly
rustup component add rustfmt clippy
```

**Windows (PowerShell):**
```powershell
# Install rustup (download rustup-init.exe from https://rustup.rs)
rustup-init.exe -y

# Install toolchains
rustup default stable
rustup toolchain install nightly
rustup component add miri --toolchain nightly
rustup component add rustfmt clippy
```

### 2.3 Python SDK (`sdk/`)
We use `uv` for blazing fast, reproducible Python environment management.

**Linux / macOS:**
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Setup Verification Environment
cd sdk
uv venv .venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

**Windows (PowerShell):**
```powershell
# Install uv
irm https://astral.sh/uv/install.sh | iex

# Setup Verification Environment
cd sdk
uv venv .venv
.venv\Scripts\activate
uv pip install -e ".[dev]"
```

---

## 3. Build & Test Workflow

### 3.1 Rust Backend
Located in `lilith-zero/`.

```bash
cd lilith-zero

# Build Optimized Binary
cargo build --release

# Run Unit Tests
cargo test

# Run Static Analysis (Clippy)
cargo clippy -- -D warnings

# Format Code
cargo fmt --check

# [Advanced] Run Miri (Undefined Behavior Detection)
# Note: Isolation disabled to allow OS clock access
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --lib
```

### 3.2 Python SDK
Located in `sdk/`.

```bash
cd sdk

# Run Red Team / Security Tests
pytest tests/red_team

# Run Integration Tests (Requires built binary)
# Linux/macOS
export LILITH_ZERO_BINARY_PATH="../lilith-zero/target/release/lilith-zero"
pytest tests/integration

# Windows ($PWD resolves to current dir)
$env:LILITH_ZERO_BINARY_PATH = "$PWD/../lilith-zero/target/release/lilith-zero.exe"
pytest tests/integration
```

---

## 4. Audit Log Verification

`lilith-zero` uses a **file-based audit logging** architecture. Logs are cryptographically signed and written to a secure file, not stderr.

### How to Verify Manually
1.  **Build the binary** (see 3.1).
2.  **Run the verification script** (in root of repo):

    ```bash
    # Linux/macOS
    export LILITH_ZERO_BINARY_PATH="$(pwd)/lilith-zero/target/release/lilith-zero"
    python3 verify_file_audit.py
    ```

    ```powershell
    # Windows
    $env:LILITH_ZERO_BINARY_PATH = "$PWD/lilith-zero/target/release/lilith-zero.exe"
    python verify_file_audit.py
    ```

3.  **Expected Output**:
    - "Connected. Checking initial audit logs..."
    - "Call tool (expecting fail)..."
    - "File-based audit log verified successfully!"

---

## 5. Contribution Standards

- **Commits**: Follow [Conventional Commits](https://www.conventionalcommits.org/).
- **Formatting**:
    - Rust: `cargo fmt`
    - Python: `ruff format`
- **Linting**:
    - Rust: `cargo clippy -- -D warnings`
    - Python: `ruff check`

Ensure all checks pass before submitting a PR.
