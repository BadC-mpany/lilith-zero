---
name: google_oss_management
description: enforces Google-grade open source standards for the Lilith project, handling Rust/Python testing, changelogs, and version control with strict human confirmation.
version: 1.1.0
---

# Google-Grade Open Source Project Management (Lilith Edition)

This skill enforces strict engineering rigor for the **Lilith** project (`C:\Users\Peter\Documents\proj\active\bad\sentinel\`). It mandates that no code is committed without passing the specific CI workflows defined in `.github/workflows/ci.yml`.

## When to use this skill
- **Ready to Commit:** When the user wants to commit changes, push code, or release a new version.
- **Workflow Updates:** When the user modifies `.github/workflows/ci.yml` or build configurations (`sentinel/Cargo.toml`, `lilith_zero/pyproject.toml`).
- **Documentation:** When generating `CHANGELOG.md` updates based on recent diffs.
- **Quality Gate:** When requested to "finalize" or "polish" a feature for merging.

## How to use it

### 1. Pre-Commit Workflow Validation (The "Green Build" Rule)
Before generating any commit messages, you MUST ask the user to run the relevant verification commands. Do not assume pass.

#### A. Rust Core Changes (`lilith-zero\`)
If changes touch `lilith-zero\src`, `lilith-zero\Cargo.toml`, or `lilith-zero\tests`:
1.  **Format & Lint:**
    *   `cd lilith-zero; cargo fmt --all -- --check`
    *   `cd lilith-zero; cargo clippy --all-targets --all-features -- -D warnings`
2.  **Test:**
    *   `cd lilith-zero; cargo test --all-features`
3.  **Audit (Optional):**
    *   `cd lilith-zero; cargo audit`

#### B. Python SDK Changes (`lilith_zero\`)
If changes touch `lilith_zero\`, `lilith_zero\src`, or `pyproject.toml`:
1.  **Lint:**
    *   `ruff check lilith_zero --ignore E501`
2.  **Type Check:**
    *   `mypy lilith_zero\src --ignore-missing-imports`
3.  **Test:**
    *   `python -m pytest tests -v --ignore=tests\test_integration.py`

#### C. Integration/Full System
If changes affect the interaction between Rust and Python:
1.  **Build Rust Binary:**
    *   `cd lilith-zero; cargo build --release`
    *   *Note: Set env var:* `$env:LILITH_ZERO_BINARY_PATH = "lilith-zero\target\release\lilith-zero.exe"`
2.  **Run Integration Test:**
4.  **Sandbox Verification (Windows/Linux):**
    *   `cd lilith-zero; cargo run --example sandbox_check`

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
"I see changes in `lilith-zero\src\policy\policy_validator.rs`.
1. **Verification Required:**
   *   `cd lilith-zero; cargo fmt --all -- --check; cargo clippy --all-targets --all-features -- -D warnings; cargo test --all-features`
2. **Changelog Draft:**
   *   `### Fixed`
   *   `- **core/policy**: Strengthened validation logic in `policy_validator.rs` to reject ambiguous rules.`
3. **Proposed Commit:**
   *   `fix(core): reject ambiguous rules in policy validator`
   *   `git add lilith-zero\src\policy\policy_validator.rs`
   *   `git commit -m "fix(core): reject ambiguous rules in policy validator"`
*Do you authorize the test run and subsequent commit?*"
