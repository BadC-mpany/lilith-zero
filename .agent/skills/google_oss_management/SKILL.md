---
name: google_oss_management
description: enforces Google-grade open source standards for the Sentinel project, handling Rust/Python testing, changelogs, and version control with strict human confirmation.
version: 1.1.0
---

# Google-Grade Open Source Project Management (Sentinel Edition)

This skill enforces strict engineering rigor for the **Sentinel** project (`C:\Users\Peter\Documents\proj\active\bad\sentinel\`). It mandates that no code is committed without passing the specific CI workflows defined in `.github/workflows/ci.yml`.

## When to use this skill
- **Ready to Commit:** When the user wants to commit changes, push code, or release a new version.
- **Workflow Updates:** When the user modifies `.github/workflows/ci.yml` or build configurations (`sentinel/Cargo.toml`, `sentinel_sdk/pyproject.toml`).
- **Documentation:** When generating `CHANGELOG.md` updates based on recent diffs.
- **Quality Gate:** When requested to "finalize" or "polish" a feature for merging.

## How to use it

### 1. Pre-Commit Workflow Validation (The "Green Build" Rule)
Before generating any commit messages, you MUST ask the user to run the relevant verification commands. Do not assume pass.

#### A. Rust Core Changes (`sentinel\`)
If changes touch `sentinel\src`, `sentinel\Cargo.toml`, or `sentinel\tests`:
1.  **Format & Lint:**
    *   `cd sentinel; cargo fmt --all -- --check`
    *   `cd sentinel; cargo clippy --all-targets --all-features -- -D warnings`
2.  **Test:**
    *   `cd sentinel; cargo test --all-features`
3.  **Audit (Optional):**
    *   `cd sentinel; cargo audit`

#### B. Python SDK Changes (`sentinel_sdk\`)
If changes touch `sentinel_sdk\`, `sentinel_sdk\src`, or `pyproject.toml`:
1.  **Lint:**
    *   `ruff check sentinel_sdk --ignore E501`
2.  **Type Check:**
    *   `mypy sentinel_sdk\src --ignore-missing-imports`
3.  **Test:**
    *   `python -m pytest tests -v --ignore=tests\test_integration.py`

#### C. Integration/Full System
If changes affect the interaction between Rust and Python:
1.  **Build Rust Binary:**
    *   `cd sentinel; cargo build --release`
    *   *Note: Set env var:* `$env:SENTINEL_BINARY_PATH = "sentinel\target\release\sentinel.exe"`
2.  **Run Integration Test:**
4.  **Sandbox Verification (Windows/Linux):**
    *   `cd sentinel; cargo run --example sandbox_check`

### 2. Semantic Changelog Generation
Generate a technically accurate, compact changelog entry based on the diff.
1.  **Read Diffs:** Analyze `git diff --staged`.
2.  **Categorize:** Group changes into `Features`, `Fixes`, `Performance`, `Breaking Changes`, and `Internal`.
3.  **Format:** Use the "Keep a Changelog" standard (Markdown).
    *   *Format:* `- **[Scope]**: <Technical Description> (Reference to files)`
4.  **Draft Content:** Present the draft entry to the user for approval before writing to `CHANGELOG.md` (root).

### 3. Atomic Commit Protocol (Human-in-the-Loop)
Generate descriptive, conventional commit messages.
1.  **Generate Message:** Create a commit message following the **Conventional Commits** specification:
    *   Format: `<type>(<scope>): <description>`
    *   Example: `feat(middleware): enforce strict type checking in python bindings`
    *   Rules: Imperative mood, max 72 chars header, detailed body if necessary.
2.  **Command Construction:** Prepare the exact git commands.
    *   `git add <specific_files>`
    *   `git commit -m "<message>"`
    *   `git push origin <branch>`
3.  **Mandatory Confirmation:**
    *   Display the *exact* commands and the commit message.
    *   **Ask:** "Do you authorize these specific commands?"
    *   **Wait** for explicit "Yes" or "Execute" from the user.

## Examples

### Scenario: User modifies Rust Policy Engine
**User:** "I updated `policy_validator.rs` in the core."
**Agent Response:**
"I see changes in `sentinel\src\policy\policy_validator.rs`.
1. **Verification Required:**
   *   `cd sentinel; cargo fmt --all -- --check; cargo clippy --all-targets --all-features -- -D warnings; cargo test --all-features`
2. **Changelog Draft:**
   *   `### Fixed`
   *   `- **core/policy**: Strengthened validation logic in `policy_validator.rs` to reject ambiguous rules.`
3. **Proposed Commit:**
   *   `fix(core): reject ambiguous rules in policy validator`
   *   `git add sentinel\src\policy\policy_validator.rs`
   *   `git commit -m "fix(core): reject ambiguous rules in policy validator"`
*Do you authorize the test run and subsequent commit?*"
