// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

//! Thread-safe, hot-reloadable policy store for the webhook server.
//!
//! # Design
//! Policies are loaded eagerly at startup (or lazily per agent-ID when `lazy_load=true`).
//! Hot-reload atomically swaps the in-memory map while holding the write lock for
//! microseconds — parsing happens outside the lock, so requests are never stalled.
//!
//! # CLI integration surface
//! `PolicyStore` is intentionally decoupled from axum/HTTP so the future
//! `lilith-ctl` CLI can import and call `reload()` directly without pulling in
//! the HTTP stack.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;

use crate::engine_core::models::PolicyDefinition;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Statistics returned by [`PolicyStore::reload`] and [`PolicyStore::stats`].
#[derive(Debug, Clone)]
pub struct PolicyStoreStats {
    /// Number of Cedar policy sets currently in memory.
    pub cedar_count: usize,
    /// Whether a legacy YAML policy is loaded.
    pub has_legacy: bool,
    /// When the store was last (re)loaded.
    pub loaded_at: Instant,
    /// How long the last reload took.
    pub last_reload_ms: u64,
}

// ---------------------------------------------------------------------------
// Internal state — kept behind a single RwLock
// ---------------------------------------------------------------------------

struct StoreInner {
    cedar: HashMap<String, Arc<cedar_policy::PolicySet>>,
    legacy: Option<Arc<PolicyDefinition>>,
    loaded_at: Instant,
    last_reload_ms: u64,
}

// ---------------------------------------------------------------------------
// PolicyStore
// ---------------------------------------------------------------------------

/// Thread-safe, hot-reloadable container for Cedar and legacy YAML policies.
///
/// All read operations take a `tokio::sync::RwLock` read-guard (uncontested
/// unless a reload is in flight). Writes (reload) hold the lock only for the
/// pointer swap, not for parsing — so request latency impact is negligible.
pub struct PolicyStore {
    inner: Arc<RwLock<StoreInner>>,
    /// Directory to reload policies from. `None` for stores built from in-memory maps.
    policy_dir: Option<PathBuf>,
    /// When `true`, `get()` will attempt a disk load for unknown agent IDs.
    lazy_load: bool,
}

impl PolicyStore {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Build a store from an already-parsed in-memory map (tests, backward compat).
    ///
    /// `policy_dir` is required if you later want to call [`PolicyStore::reload`]
    /// or use lazy loading; pass `None` if neither is needed.
    pub fn from_map(
        cedar: HashMap<String, Arc<cedar_policy::PolicySet>>,
        legacy: Option<Arc<PolicyDefinition>>,
        policy_dir: Option<PathBuf>,
        lazy_load: bool,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreInner {
                cedar,
                legacy,
                loaded_at: Instant::now(),
                last_reload_ms: 0,
            })),
            policy_dir,
            lazy_load,
        }
    }

    /// Load all Cedar (`.cedar`) files from `dir` into the store.
    ///
    /// Files named `policy_<agent_id>.cedar` or `<agent_id>.cedar` are accepted;
    /// the `policy_` prefix is stripped automatically.
    pub async fn load_from_dir(dir: PathBuf, lazy_load: bool) -> anyhow::Result<Self> {
        let start = Instant::now();
        let (cedar, legacy) = load_dir_async(&dir).await?;
        let elapsed = start.elapsed().as_millis() as u64;

        tracing::info!(
            "PolicyStore: loaded {} Cedar policy sets from {} in {}ms",
            cedar.len(),
            dir.display(),
            elapsed
        );

        Ok(Self {
            inner: Arc::new(RwLock::new(StoreInner {
                cedar,
                legacy,
                loaded_at: Instant::now(),
                last_reload_ms: elapsed,
            })),
            policy_dir: Some(dir),
            lazy_load,
        })
    }

    /// Build an empty store (fail-closed: all lookups return `None`).
    pub fn empty() -> Self {
        Self::from_map(HashMap::new(), None, None, false)
    }

    // -----------------------------------------------------------------------
    // Read operations
    // -----------------------------------------------------------------------

    /// Look up the Cedar [`PolicySet`] for `agent_id`.
    ///
    /// Fast path: uncontested read-lock + HashMap lookup, ~100–200 ns.
    /// Lazy-load slow path: drops read lock, acquires write lock, loads from disk.
    pub async fn get(&self, agent_id: &str) -> Option<Arc<cedar_policy::PolicySet>> {
        // Fast path
        {
            let inner = self.inner.read().await;
            if let Some(p) = inner.cedar.get(agent_id) {
                return Some(p.clone());
            }
        }

        // Lazy-load slow path
        if self.lazy_load {
            if let Some(dir) = &self.policy_dir {
                return self.lazy_load_agent(agent_id, dir).await;
            }
        }

        None
    }

    /// Return the legacy YAML [`PolicyDefinition`], if any.
    pub async fn get_legacy(&self) -> Option<Arc<PolicyDefinition>> {
        self.inner.read().await.legacy.clone()
    }

    /// Return the directory policies are loaded from, if any.
    pub fn policy_dir(&self) -> Option<&PathBuf> {
        self.policy_dir.as_ref()
    }

    /// Return `true` if neither Cedar nor legacy policies are loaded.
    pub async fn is_empty(&self) -> bool {
        let inner = self.inner.read().await;
        inner.cedar.is_empty() && inner.legacy.is_none()
    }

    /// Return current store statistics (for the `/admin/status` endpoint).
    pub async fn stats(&self) -> PolicyStoreStats {
        let inner = self.inner.read().await;
        PolicyStoreStats {
            cedar_count: inner.cedar.len(),
            has_legacy: inner.legacy.is_some(),
            loaded_at: inner.loaded_at,
            last_reload_ms: inner.last_reload_ms,
        }
    }

    // -----------------------------------------------------------------------
    // Reload
    // -----------------------------------------------------------------------

    /// Atomically reload all policies from [`policy_dir`](Self::policy_dir).
    ///
    /// Parsing happens outside the lock; the write lock is held only for the
    /// HashMap pointer swap (microseconds). In-flight requests see either the
    /// old or the new policy set — never a partial mix.
    ///
    /// Returns an error if `policy_dir` is not set or the directory is
    /// unreadable. Does not touch the in-memory state on error (fail-safe).
    pub async fn reload(&self) -> anyhow::Result<PolicyStoreStats> {
        let dir = self.policy_dir.as_ref().ok_or_else(|| {
            anyhow::anyhow!("PolicyStore has no policy_dir configured — reload is not supported")
        })?;

        let start = Instant::now();

        // Phase 1: parse files WITHOUT holding the lock
        let (new_cedar, new_legacy) = load_dir_async(dir).await?;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        // Phase 2: swap atomically
        let count = new_cedar.len();
        let has_legacy = new_legacy.is_some();
        let loaded_at = {
            let mut inner = self.inner.write().await;
            inner.cedar = new_cedar;
            inner.legacy = new_legacy;
            inner.loaded_at = Instant::now();
            inner.last_reload_ms = elapsed_ms;
            inner.loaded_at
        };

        tracing::info!(
            "PolicyStore: reloaded {} Cedar policy sets in {}ms",
            count,
            elapsed_ms
        );

        Ok(PolicyStoreStats {
            cedar_count: count,
            has_legacy,
            loaded_at,
            last_reload_ms: elapsed_ms,
        })
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Double-checked lazy load for a single agent ID.
    ///
    /// File I/O and Cedar parsing run on a blocking thread so the async runtime
    /// is never stalled during disk access.
    async fn lazy_load_agent(
        &self,
        agent_id: &str,
        dir: &Path,
    ) -> Option<Arc<cedar_policy::PolicySet>> {
        let agent_id_owned = agent_id.to_string();
        let dir_owned = dir.to_path_buf();

        // Disk read + Cedar parse on a blocking thread.
        let blocking_result = tokio::task::spawn_blocking(move || {
            let with_prefix = dir_owned.join(format!("policy_{agent_id_owned}.cedar"));
            let without_prefix = dir_owned.join(format!("{agent_id_owned}.cedar"));

            let path = if with_prefix.exists() {
                with_prefix
            } else if without_prefix.exists() {
                without_prefix
            } else {
                return Ok(None);
            };

            let content = std::fs::read_to_string(&path)
                .map_err(|e| format!("read '{}': {e}", path.display()))?;
            let ps = cedar_policy::PolicySet::from_str(&content)
                .map_err(|e| format!("parse '{}': {e}", path.display()))?;
            Ok::<Option<Arc<cedar_policy::PolicySet>>, String>(Some(Arc::new(ps)))
        })
        .await;

        let policy_set = match blocking_result {
            Ok(Ok(Some(ps))) => ps,
            Ok(Ok(None)) => {
                tracing::debug!(
                    "PolicyStore lazy-load: no Cedar file found for agent '{}'",
                    agent_id
                );
                return None;
            }
            Ok(Err(e)) => {
                tracing::error!("PolicyStore lazy-load failed for '{}': {}", agent_id, e);
                return None;
            }
            Err(e) => {
                tracing::error!(
                    "PolicyStore lazy-load task panicked for '{}': {}",
                    agent_id,
                    e
                );
                return None;
            }
        };

        // Write lock: double-check then insert
        let mut inner = self.inner.write().await;
        // Another task may have inserted this agent_id between our read-lock drop
        // and write-lock acquire — return theirs to avoid a redundant overwrite.
        if let Some(existing) = inner.cedar.get(agent_id) {
            return Some(existing.clone());
        }
        inner.cedar.insert(agent_id.to_string(), policy_set.clone());
        tracing::info!("PolicyStore lazy-loaded policy for agent '{}'", agent_id);
        Some(policy_set)
    }
}

// ---------------------------------------------------------------------------
// Directory loading (used by load_from_dir and reload)
// ---------------------------------------------------------------------------

type DirLoadResult = (
    HashMap<String, Arc<cedar_policy::PolicySet>>,
    Option<Arc<PolicyDefinition>>,
);

/// Load all `.cedar` files in `dir` and return a parsed map keyed by agent ID.
///
/// Run on a blocking thread pool since file I/O is synchronous.
async fn load_dir_async(dir: &Path) -> anyhow::Result<DirLoadResult> {
    let dir = dir.to_owned();
    tokio::task::spawn_blocking(move || load_dir_sync(&dir))
        .await
        .map_err(|e| anyhow::anyhow!("policy load task panicked: {e}"))?
}

fn load_dir_sync(dir: &Path) -> anyhow::Result<DirLoadResult> {
    if !dir.exists() {
        return Err(anyhow::anyhow!(
            "policy directory does not exist: {}",
            dir.display()
        ));
    }

    let mut cedar: HashMap<String, Arc<cedar_policy::PolicySet>> = HashMap::new();
    let mut legacy: Option<Arc<PolicyDefinition>> = None;

    let entries = std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("cannot read policy directory '{}': {e}", dir.display()))?;

    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match ext {
            "cedar" => {
                let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                let agent_id = stem.strip_prefix("policy_").unwrap_or(stem);

                let content = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", path.display()))?;

                let policy_set = cedar_policy::PolicySet::from_str(&content).map_err(|e| {
                    anyhow::anyhow!("cannot parse Cedar policy '{}': {e}", path.display())
                })?;

                cedar.insert(agent_id.to_string(), Arc::new(policy_set));
            }
            "yaml" | "yml" => {
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", path.display()))?;
                match serde_yaml_ng::from_str::<PolicyDefinition>(&content) {
                    Ok(pol) => {
                        legacy = Some(Arc::new(pol));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "PolicyStore: skipping '{}' (YAML parse error: {})",
                            path.display(),
                            e
                        );
                    }
                }
            }
            _ => {}
        }
    }

    Ok((cedar, legacy))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    const MINIMAL_CEDAR: &str = r#"
permit(
  principal,
  action == Action::"invoke_tool",
  resource == Tool::"test_tool"
);
"#;

    fn write_cedar_policy(dir: &Path, agent_id: &str, content: &str) {
        let path = dir.join(format!("{agent_id}.cedar"));
        let mut f = std::fs::File::create(&path).expect("create cedar file");
        f.write_all(content.as_bytes()).expect("write cedar");
    }

    fn write_cedar_policy_prefixed(dir: &Path, agent_id: &str, content: &str) {
        let path = dir.join(format!("policy_{agent_id}.cedar"));
        let mut f = std::fs::File::create(&path).expect("create cedar file");
        f.write_all(content.as_bytes()).expect("write cedar");
    }

    #[tokio::test]
    async fn loads_cedar_files_from_dir() {
        let tmp = TempDir::new().unwrap();
        write_cedar_policy(tmp.path(), "agent-1", MINIMAL_CEDAR);
        write_cedar_policy_prefixed(tmp.path(), "agent-2", MINIMAL_CEDAR);

        let store = PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
            .await
            .unwrap();

        assert!(!store.is_empty().await);
        assert!(store.get("agent-1").await.is_some());
        assert!(store.get("agent-2").await.is_some());
        assert!(store.get("agent-unknown").await.is_none());
    }

    #[tokio::test]
    async fn reload_swaps_policies_atomically() {
        let tmp = TempDir::new().unwrap();
        write_cedar_policy(tmp.path(), "agent-1", MINIMAL_CEDAR);

        let store = PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
            .await
            .unwrap();

        assert!(store.get("agent-1").await.is_some());
        assert!(store.get("agent-2").await.is_none());

        // Add a new policy file and reload
        write_cedar_policy(tmp.path(), "agent-2", MINIMAL_CEDAR);
        let stats = store.reload().await.unwrap();

        assert_eq!(stats.cedar_count, 2);
        assert!(
            store.get("agent-1").await.is_some(),
            "existing policy retained"
        );
        assert!(
            store.get("agent-2").await.is_some(),
            "new policy visible after reload"
        );
    }

    #[tokio::test]
    async fn reload_removes_deleted_policies() {
        let tmp = TempDir::new().unwrap();
        write_cedar_policy(tmp.path(), "agent-1", MINIMAL_CEDAR);
        write_cedar_policy(tmp.path(), "agent-2", MINIMAL_CEDAR);

        let store = PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
            .await
            .unwrap();
        assert_eq!(store.stats().await.cedar_count, 2);

        // Remove agent-2's file and reload
        std::fs::remove_file(tmp.path().join("agent-2.cedar")).unwrap();
        store.reload().await.unwrap();

        assert!(store.get("agent-1").await.is_some());
        assert!(
            store.get("agent-2").await.is_none(),
            "deleted policy removed after reload"
        );
    }

    #[tokio::test]
    async fn lazy_load_fetches_on_first_access() {
        let tmp = TempDir::new().unwrap();
        // Start with empty store (no eager load)
        let store = PolicyStore::from_map(
            HashMap::new(),
            None,
            Some(tmp.path().to_path_buf()),
            true, // lazy_load = true
        );

        // Policy file doesn't exist yet → None
        assert!(store.get("agent-1").await.is_none());

        // Write the file and try again
        write_cedar_policy(tmp.path(), "agent-1", MINIMAL_CEDAR);
        let policy = store.get("agent-1").await;
        assert!(policy.is_some(), "lazy load should find newly written file");

        // Second call should use the cached version (still returns Some)
        assert!(store.get("agent-1").await.is_some());
    }

    #[tokio::test]
    async fn get_returns_none_without_lazy_load() {
        let tmp = TempDir::new().unwrap();
        write_cedar_policy(tmp.path(), "agent-1", MINIMAL_CEDAR);

        // lazy_load = false: files exist on disk but are never loaded automatically
        let store =
            PolicyStore::from_map(HashMap::new(), None, Some(tmp.path().to_path_buf()), false);

        assert!(store.get("agent-1").await.is_none());
    }

    #[tokio::test]
    async fn reload_without_policy_dir_returns_error() {
        let store = PolicyStore::empty();
        assert!(store.reload().await.is_err());
    }

    #[tokio::test]
    async fn from_map_stores_policies() {
        let mut map = HashMap::new();
        let ps = cedar_policy::PolicySet::from_str(MINIMAL_CEDAR).unwrap();
        map.insert("my-agent".to_string(), Arc::new(ps));

        let store = PolicyStore::from_map(map, None, None, false);
        assert!(store.get("my-agent").await.is_some());
        assert!(store.get("other-agent").await.is_none());
    }

    #[tokio::test]
    async fn concurrent_reads_during_reload_are_consistent() {
        let tmp = TempDir::new().unwrap();
        write_cedar_policy(tmp.path(), "agent-1", MINIMAL_CEDAR);

        let store = Arc::new(
            PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
                .await
                .unwrap(),
        );

        // Spawn many concurrent readers and a reloader simultaneously
        let mut handles = vec![];

        let store_clone = store.clone();
        handles.push(tokio::spawn(async move {
            store_clone.reload().await.expect("reload failed");
        }));

        for _ in 0..20 {
            let s = store.clone();
            handles.push(tokio::spawn(async move {
                // Every read must return a consistent result (not panic, not corrupt)
                let _ = s.get("agent-1").await;
            }));
        }

        for h in handles {
            h.await.expect("task panicked");
        }
    }

    #[tokio::test]
    async fn stats_reflect_current_state() {
        let tmp = TempDir::new().unwrap();
        write_cedar_policy(tmp.path(), "agent-1", MINIMAL_CEDAR);
        write_cedar_policy(tmp.path(), "agent-2", MINIMAL_CEDAR);

        let store = PolicyStore::load_from_dir(tmp.path().to_path_buf(), false)
            .await
            .unwrap();

        let stats = store.stats().await;
        assert_eq!(stats.cedar_count, 2);
        assert!(!stats.has_legacy);
    }
}
