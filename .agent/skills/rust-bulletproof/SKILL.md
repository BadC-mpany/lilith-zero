---
name: rust_bulletproof
description: enforces advanced correctness standards for Sentinel's Rust core using fuzzing, property testing, and Miri.
version: 1.0.0
---

# Rust Bulletproof: Advanced Verification Strategy

This skill goes beyond standard unit testing to ensure the mathematical correctness and memory safety of Sentinel's critical Rust path (`sentinel\src`). It employs fuzzing, property-based testing, and interpreter-based verification.

## When to use this skill
- **Critical Logic Changes:** Modifications to `policy_validator.rs`, `pattern_matcher.rs`, or `security.rs`.
- **Parsing/Input Handling:** Changes to how external data (YAML, JSON, Byte streams) is ingested.
- **Unsafe Code:** ANY addition or modification of `unsafe` blocks.
- **Concurrency:** Changes involving `Tokio`, `Mutex`, or `RwLock`.

## How to use it

### 1. The "No-Panic" Policy (Property Testing)
Use `proptest` to mathematically assert that functions never panic and properties hold for *all* inputs, not just example cases.

**Command:**
```powershell
# Run property tests specifically (usually marked with #[test])
cd sentinel; cargo test --package sentinel --test properties
```
*Note: If `tests\properties.rs` does not exist, ask the user to create a property test for the new feature.*

### 2. Undefined Behavior Check (Miri)
If the code uses `unsafe` or does complex pointer arithmetic, you MUST run Miri. Miri interprets the code to find memory leaks, data races, and misalignment.

**Command:**
```powershell
# Install Miri if missing
rustup component add miri
# Run tests under Miri
cd sentinel; cargo miri test
```

### 3. Fuzzing Campaign
For parsers and security boundaries, run a short fuzzing campaign to find edge case crashes.

**Command:**
```powershell
# Ensure cargo-fuzz is installed
cargo install cargo-fuzz
# Initialize if needed: cargo fuzz init
# Run the relevant target (e.g., policy_parser)
cd sentinel; cargo fuzz run policy_parser -- -max_total_time=300 # 5 minutes
```

### 4. Mutation Testing (The "Test the Tests" Rule)
Verify that your tests are actually checking the code by introducing random bugs (mutants) and ensuring tests fail.

**Command:**
```powershell
# Install cargo-mutants
cargo install cargo-mutants
# Run mutation tests
cd sentinel; cargo mutants
```

## Workflow Example

**User:** "I optimized the `PolicyMatcher` using raw pointers for speed."
**Agent Response:**
"Since you modified `PolicyMatcher` with `unsafe` code:
1. **Miri Check (CRITICAL):**
   `cd sentinel; cargo miri test` - *Must pass without UB.*
2. **Property Test:**
   `cd sentinel; cargo test test_policy_matcher_properties` - *Verify invariants hold.*
3. **Fuzzing:**
   `cd sentinel; cargo fuzz run matcher_fuzz` - *Run for 5 minutes.*

*Would you like me to construct a property test scaffold for this optimization?*"
