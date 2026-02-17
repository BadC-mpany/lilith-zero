# Verified Security

Lilith Zero uses [Kani](https://model-checking.github.io/kani/), a Rust model checker backed by the CBMC bounded model checker, to **mathematically prove** that critical security invariants in the middleware's core components hold for all possible inputs — not just test cases.

## Why Formal Verification?

Unit tests check specific inputs. Fuzzing explores random inputs. **Formal verification exhaustively proves properties over all reachable states.** For a security middleware's internal components, this distinction matters:

- A missed edge case in content-length parsing = buffer overflow.
- A broken taint logic = data exfiltration.
- A wrong deny-by-default check = unauthorized tool access.

## Verified Invariants

We maintain **13 proof harnesses** that collectively verify the security-critical logic:

### Deny-by-Default & Access Control

| Proof | Property |
| :--- | :--- |
| `prove_deny_by_default` | Unknown tools are **always denied** (fail-closed). |
| `prove_static_deny_supremacy` | Static DENY rules **short-circuit** before any taint evaluation. |

### Taint Monotonicity (IFC)

| Proof | Property |
| :--- | :--- |
| `prove_taint_monotonicity` | ADD_TAINT preserves all pre-existing tags (no silent drops). |
| `prove_taint_removal_is_explicit` | Only tags explicitly in `taints_to_remove` are removed. |
| `prove_taint_monotonicity_symbolic` | **Exhaustive**: over all 2^6 initial×add combinations, no tag vanishes without removal. |

### Lethal Trifecta

| Proof | Property |
| :--- | :--- |
| `prove_lethal_trifecta_blocks` | Both `ACCESS_PRIVATE` + `UNTRUSTED_SOURCE` → always blocks. |
| `prove_lethal_trifecta_no_false_positive` | One taint alone does **not** trigger a block. |
| `prove_lethal_trifecta_symbolic` | **Exhaustive**: blocks IFF both taints present, for all 4 combinations. |

### Policy Logic

| Proof | Property |
| :--- | :--- |
| `prove_forbidden_tags_or_semantics` | `CHECK_TAINT` blocks if **any** forbidden tag is present (OR-logic). |
| `prove_forbidden_tags_symbolic` | **Exhaustive**: OR-logic holds for all 4 input combos. |
| `prove_required_taints_and_semantics` | `CHECK_TAINT` blocks only when **all** required tags are present (AND-logic). |

### Protocol Safety

| Proof | Property |
| :--- | :--- |
| `prove_content_length_no_overflow` | Content-length comparison is total and cast is overflow-safe. |
| `prove_recursion_depth_terminates` | Logic condition evaluation terminates at depth > 50. |

## Running Verification

The harnesses run inside a Docker container with Kani pre-installed. All 13 proofs run in a **single compilation pass**:

```bash title="Terminal"
./lilith-zero/run_kani.ps1
```

```text title="Output"
========================================================
              KANI VERIFICATION REPORT
========================================================

  [PASS] prove_deny_by_default
  [PASS] prove_static_deny_supremacy
  [PASS] prove_taint_monotonicity
  [PASS] prove_taint_removal_is_explicit
  [PASS] prove_taint_monotonicity_symbolic
  [PASS] prove_lethal_trifecta_blocks
  [PASS] prove_lethal_trifecta_no_false_positive
  [PASS] prove_lethal_trifecta_symbolic
  [PASS] prove_forbidden_tags_or_semantics
  [PASS] prove_forbidden_tags_symbolic
  [PASS] prove_required_taints_and_semantics
  [PASS] prove_content_length_no_overflow
  [PASS] prove_recursion_depth_terminates

  Complete - 13 successfully verified harnesses, 0 failures, 13 total.

  All 13 proofs verified successfully.
```

!!! tip "CI Integration"
    Formal verification runs automatically in the security suite via `scripts/run_security_suite.ps1`. Every push to `main` re-verifies all proofs.

## Design Notes

All proofs are written as **pure boolean logic** — no `HashMap`, `HashSet`, `String`, or `Vec`. This is intentional: CBMC's SipHash loop unwinding causes solver timeouts when verifying code with Rust's standard hash collections. The taint set is modeled as individual boolean flags with identical semantics to `HashSet::insert` / `HashSet::remove` / `HashSet::contains`.

Real `HashSet`-based integration tests validate the same properties at runtime in the `#[cfg(test)]` section of `verification.rs`.

## Source

The verification harnesses are defined in [`verification.rs`](https://github.com/BadC-mpany/lilith-zero/blob/main/lilith-zero/src/verification.rs).
