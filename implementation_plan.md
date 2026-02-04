# Implementation Plan: Minimalist "Google-Grade" Sandboxing

## Goal
Refactor the Sentinel Sandbox to be **minimalist**, **explicit**, and **secure-by-default**.
Remove "magic" auto-discovery (which creates vulnerabilities and complexity) and replace it with a **Deno-inspired Permission Model** and **Explicit Runtime Profiles**.

## Core Philosophy
1.  **Deny Everything**: The sandbox starts with 0 permissions. No network, no file access, no env vars.
2.  **Explicit Grants**: Permissions are added explicitly (e.g., `allow_read(path)`).
3.  **No Heuristics**: The sandbox does not guess. It obeys.
4.  **Profile Overlays**: For convenience, we provide "Profiles" (e.g., `PythonProfile`) that *generate* the necessary specific grants for a runtime, given a trusted input path.

## Architecture Refactor

### 1. The Permission Model (`src/core/policy.rs`)
Remove the ad-hoc `SandboxConfig` and define a strict Policy Struct based on the Deno model.

```rust
pub struct SandboxPolicy {
    pub allow_network: bool,       // Default: false
    pub allow_env: bool,           // Default: false (or specific list)
    pub read_paths: Vec<PathBuf>,  // Default: empty
    pub write_paths: Vec<PathBuf>, // Default: empty
    pub allow_images: bool,        // (Future)
}
```

### 2. The Sandbox Builder (`src/sandbox/builder.rs`)
A clean, fluent API for constructing sandboxes.

```rust
let sandbox = Sandbox::new(binary_path)
    .with_policy(policy)
    .with_profile(PythonProfile::new(venv_path)) // Optional overlay
    .spawn()
    .await?;
```

### 3. Profiles (`src/sandbox/profiles/`)
Instead of "RuntimeDiscovery" (inference), we use "Profiles" (explicit configuration).

*   **`mod.rs`**: Trait `SandboxProfile { fn apply(&self, policy: &mut SandboxPolicy); }`
*   **`python.rs`**: 
    *   Input: `venv_path` (Trusted).
    *   Logic: Adds `venv/Scripts`, `venv/Lib`, `venv/Include` to `read_paths`. 
    *   NO execution of python to "ask" it. We know the layout of a venv.
*   **`node.rs`**:
    *   Input: `project_root`.
    *   Logic: Adds `node_modules` to `read_paths`.

### 4. Backends (`src/sandbox/backends/`)
Keep the OS-specific implementations but simplify their interfaces to consume the `SandboxPolicy` directly.

*   **Windows**: AppContainer/LPAC.
    *   Strictly map `read_paths` to file ACL grants.
    *   Network -> `InternetClient` capability.
*   **Linux**: Landlock.
    *   Strictly map `read_paths` to landlock rules.
*   **macOS**: Seatbelt.
    *   Generate a `.sb` profile string from the policy.

## Implementation Steps

1.  **Delete `RuntimeDiscovery`**: Remove `src/mcp/sandbox/runtime.rs` and its complexities.
2.  **Create `SandboxPolicy`**: Define the clean config structure.
3.  **Implement `PythonProfile`**: Write the logic to whitelist standard venv layouts based on a provided root path.
4.  **Refactor `main.rs`**: Update CLI to accept explicit flags (Deno-style) or a simplified Policy YAML.
    *   `--allow-read ./data`
    *   `--allow-net`
    *   `--language-profile python:/path/to/venv` (New explicit flag)
5.  **Refactor Backend**: Update `windows.rs` etc. to use the new simple Policy struct.

## Verification
*   **Security**: The "Confused Deputy" vulnerability is eliminated because we never ask the runtime what it wants. We tell it what it gets.
*   **Simplicity**: Code size reduced (no introspection, no regex parsing).
*   **Usability**: User explicitly sees what they are granting via flags or simple config.

## Success Criteria
*   The `test_sandbox_exfil.py` passes using the new `PythonProfile` model.
*   The code is significantly smaller and easier to read.
*   No "magic" warnings in the logs.
