# Taint Persistence — Resolved

The bugs documented here were fixed on 2026-05-05. This file is kept as a brief post-mortem.

## Root causes (both fixed)

**1. Cedar `@id` annotation ≠ PolicyId**

Cedar auto-assigns policy IDs as `policy0`, `policy1`, … when parsing a `.cedar` file.
The `@id("add_taint:UNTRUSTED_SOURCE:search")` syntax sets a user *annotation*, not the PolicyId.

The old code called `policy_id.to_string()` in the taint-extraction loop, which returned `"policy4"`
etc. and never matched the `"add_taint:"` prefix — so no taints were ever added.

Fix: `cedar_eval.get_policy_annotation(policy_id, "id")` reads the `@id` annotation value,
which is then checked for the `add_taint:`/`remove_taint:` prefix.
See `engine_core/security_core.rs` (~line 391 and ~line 529).

**2. Session files written to ephemeral `/root` instead of persistent `/home`**

The Dockerfile pre-created `/home/.lilith/sessions` but never set `LILITH_ZERO_SESSION_STORAGE_DIR`.
The app defaulted to `$HOME/.lilith/sessions` = `/root/.lilith/sessions` (ephemeral, lost on cold start).

Fix: `ENV LILITH_ZERO_SESSION_STORAGE_DIR=/home/.lilith/sessions` in the Dockerfile.
The Azure App Service app setting with the same value was also added as belt-and-suspenders.

## Verified

End-to-end 4-step lethal trifecta test passes on Azure:
1. SearchWeb → `ALLOW`, adds `UNTRUSTED_SOURCE`
2. SendEmail → `ALLOW` (only one taint)
3. ReadEmails → `ALLOW`, adds `ACCESS_PRIVATE`
4. SendEmail → **`BLOCK`** — "Blocked by lethal trifecta protection"
