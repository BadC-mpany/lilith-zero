# Formal Verification

Lilith Zero uses [Kani](https://model-checking.github.io/kani/), a Rust model checker backed by the CBMC bounded model checker, to **mathematically prove** that critical security invariants hold for all possible inputs — not just test cases.

## Why Formal Verification?

Unit tests check specific inputs. Fuzzing explores random inputs. **Formal verification exhaustively proves properties over all reachable states.** For a security middleware, this distinction matters:

- A missed edge case in content-length parsing = buffer overflow.
- A weak session ID = session hijacking.
- A broken taint-clean transition = data exfiltration.

## Verified Properties

### `prove_content_length_no_overflow`

Proves that the content-length parser in the JSON-RPC framing layer **cannot overflow** on any valid input size.

- **Property**: For all `u64` values representable within the protocol's size constraints, arithmetic operations on content length do not wrap or panic.
- **Checks verified**: 2 assertions, 0 failures.

### `prove_session_id_format`

Proves that generated session IDs meet minimum entropy and length requirements.

- **Property 1**: Session ID must be at least 101 characters.
- **Property 2**: Session ID must contain at least 256 bits of entropy.
- **Checks verified**: 2 assertions, 0 failures.

### `prove_taint_clean_logic`

Proves that the taint state machine transitions are correct — specifically, that cleaning a taint actually removes it and that the Lethal Trifecta detection logic is sound.

- **Property**: For all combinations of taint flags, the `clean` operation and the trifecta check produce correct results.
- **Checks verified**: 218 assertions (including stdlib checks), 0 failures.

## Running Verification

The harnesses run inside a Docker container with Kani pre-installed:

```bash
# Run all Kani harnesses
./lilith-zero/run_kani.ps1
```

!!! tip "CI Integration"
    Formal verification runs automatically in the security suite via `scripts/run_security_suite.ps1`. Every push to `main` re-verifies all proofs.

## Source

The verification harnesses are defined in [`verification.rs`](https://github.com/BadC-mpany/lilith-zero/blob/main/lilith-zero/src/verification.rs).
