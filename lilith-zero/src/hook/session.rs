// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

//! Shared session identity utilities used by multiple hook adapters.
//!
//! Adapters that have no native session identifier (Copilot CLI, VS Code when
//! `sessionId` is absent) call [`derive_session_id`] to produce a stable,
//! per-workspace session key from the workspace path.

use sha2::{Digest, Sha256};

/// Derive a stable, filesystem-safe session ID from a workspace path.
///
/// Used by adapters that have no native session identifier (Copilot CLI,
/// VS Code fallback). The `cwd` (current working directory) is hashed with
/// SHA-256 to produce a deterministic, per-workspace session key. The first
/// 16 bytes of the hash give 128 bits of uniqueness — identical to UUID v4
/// entropy and sufficient to avoid accidental collisions across any realistic
/// set of developer workspaces.
///
/// The `copilot-` prefix distinguishes these derived IDs from explicitly
/// supplied session IDs in shared audit logs and the `~/.lilith/sessions/` store.
///
/// # Security properties
/// - Deterministic: same `cwd` always maps to the same session.
/// - Collision-resistant: different `cwd` values are overwhelmingly unlikely
///   to produce the same ID.
/// - No path traversal: the output contains only hex digits and a hyphen,
///   making it safe to use as a filename component (validated by
///   `PersistenceLayer::sanitize_session_id`).
pub fn derive_session_id(cwd: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cwd.as_bytes());
    let hash = hasher.finalize();
    format!("copilot-{}", hex::encode(&hash[..16]))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Session IDs must be deterministic: the same workspace path must always
    /// produce the same ID so that taint state persists across hook invocations.
    #[test]
    fn test_derive_session_id_is_deterministic() {
        let id1 = derive_session_id("/home/user/my-project");
        let id2 = derive_session_id("/home/user/my-project");
        assert_eq!(id1, id2, "same cwd must always produce the same session ID");
    }

    /// Different workspaces must not share a session ID — that would let taints
    /// bleed across unrelated projects.
    #[test]
    fn test_derive_session_id_different_cwds_produce_different_ids() {
        let id_a = derive_session_id("/home/user/project-a");
        let id_b = derive_session_id("/home/user/project-b");
        assert_ne!(
            id_a, id_b,
            "different cwds must produce different session IDs"
        );
    }

    /// IDs must start with "copilot-" to distinguish them from Claude Code IDs
    /// in shared audit logs and session files.
    #[test]
    fn test_derive_session_id_has_copilot_prefix() {
        let id = derive_session_id("/workspace");
        assert!(
            id.starts_with("copilot-"),
            "session ID must start with 'copilot-' but got: {id}"
        );
    }

    /// IDs must be safe as filenames: only hex digits and the prefix hyphen.
    #[test]
    fn test_derive_session_id_is_filesystem_safe() {
        let id = derive_session_id("/home/user/projects/my repo with spaces");
        for ch in id.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-',
                "session ID contains unsafe char '{ch}' in: {id}"
            );
        }
    }

    /// Empty cwd must still produce a valid (not panicking) session ID.
    #[test]
    fn test_derive_session_id_empty_cwd() {
        let id = derive_session_id("");
        assert!(
            id.starts_with("copilot-"),
            "empty cwd must still produce a valid ID"
        );
        assert!(!id.is_empty());
    }
}
