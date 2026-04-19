// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

use crate::engine_core::security_core::SessionState;
use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Manager for persisting session state to disk.
pub struct PersistenceLayer {
    storage_dir: PathBuf,
}

/// RAII guard representing a cross-process lock on a session state file.
///
/// Reads and writes go through this guard's file handle, which is the same
/// handle that holds the `LockFileEx` lock. On Windows, only the locking
/// process can access byte-range-locked regions; opening a second handle and
/// calling `ReadFile` from a different process would return
/// `ERROR_LOCK_VIOLATION`. By using a single handle for both locking and I/O
/// we avoid that entirely.
pub struct SessionLock {
    file: fs::File,
}

impl PersistenceLayer {
    /// Create a new PersistenceLayer pointing to the given directory.
    pub fn new(storage_dir: PathBuf) -> Self {
        Self { storage_dir }
    }

    /// Default persistence layer in ~/.lilith/sessions.
    pub fn default_local() -> Self {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        Self::new(PathBuf::from(home).join(".lilith").join("sessions"))
    }

    /// Acquire an exclusive cross-process lock on the session state file.
    ///
    /// Creates the storage directory and file if they do not exist. Blocks
    /// until the lock is available. Use [`SessionLock::load`] and
    /// [`SessionLock::save`] to read and write state through the locked handle.
    pub fn lock(&self, session_id: &str) -> Result<SessionLock> {
        if !self.storage_dir.exists() {
            fs::create_dir_all(&self.storage_dir)
                .with_context(|| format!("Failed to create storage dir: {:?}", self.storage_dir))?;
        }
        let file_path = self.get_file_path(session_id);

        // Open (or create) the session file. We keep this handle open for the
        // lifetime of the lock and perform all reads/writes through it so that
        // Windows `LockFileEx` byte-range locking is satisfied: only the handle
        // that owns the lock can access the locked region from other processes.
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&file_path)
            .with_context(|| format!("Failed to open lock file: {:?}", file_path))?;

        file.lock_exclusive()
            .with_context(|| format!("Failed to acquire flock on {:?}", file_path))?;

        Ok(SessionLock { file })
    }

    fn get_file_path(&self, session_id: &str) -> PathBuf {
        // Sanitize session_id to prevent path traversal.
        let safe_id = session_id
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>();
        self.storage_dir.join(format!("{}.json", safe_id))
    }
}

impl SessionLock {
    /// Read session state through the locked file handle.
    ///
    /// Returns `Ok(None)` when the file is empty (new session).
    pub fn load(&mut self) -> Result<Option<SessionState>> {
        self.file
            .seek(SeekFrom::Start(0))
            .context("Failed to seek session file")?;

        let mut json = String::new();
        self.file
            .read_to_string(&mut json)
            .context("Failed to read session state")?;

        if json.trim().is_empty() {
            return Ok(None);
        }

        let state: SessionState =
            serde_json::from_str(&json).context("Failed to deserialize session state")?;
        Ok(Some(state))
    }

    /// Write session state through the locked file handle.
    pub fn save(&mut self, state: &SessionState) -> Result<()> {
        let json =
            serde_json::to_string_pretty(state).context("Failed to serialize session state")?;

        // Truncate first so stale bytes from a larger previous write don't linger.
        self.file
            .seek(SeekFrom::Start(0))
            .context("Failed to seek session file for write")?;
        self.file
            .set_len(0)
            .context("Failed to truncate session file")?;
        self.file
            .write_all(json.as_bytes())
            .context("Failed to write session state")?;
        self.file.flush().context("Failed to flush session file")?;

        Ok(())
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
