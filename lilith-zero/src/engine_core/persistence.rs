// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

use crate::engine_core::security_core::SessionState;
use anyhow::{Context, Result};
use fs2::FileExt;
use std::fs;
use std::path::PathBuf;

/// Manager for persisting session state to disk.
pub struct PersistenceLayer {
    storage_dir: PathBuf,
}

/// RAII guard representing a cross-process lock on a session state file.
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

    /// Save state for a session.
    pub fn save(&self, session_id: &str, state: &SessionState) -> Result<()> {
        if !self.storage_dir.exists() {
            fs::create_dir_all(&self.storage_dir)
                .with_context(|| format!("Failed to create storage dir: {:?}", self.storage_dir))?;
        }

        let file_path = self.get_file_path(session_id);
        let json =
            serde_json::to_string_pretty(state).context("Failed to serialize session state")?;

        fs::write(&file_path, json)
            .with_context(|| format!("Failed to write state to {:?}", file_path))?;

        Ok(())
    }

    /// Load state for a session. Use a default if not found.
    pub fn load(&self, session_id: &str) -> Result<Option<SessionState>> {
        let file_path = self.get_file_path(session_id);
        if !file_path.exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read state from {:?}", file_path))?;

        if json.trim().is_empty() {
            return Ok(None);
        }

        let state: SessionState = serde_json::from_str(&json)
            .with_context(|| format!("Failed to deserialize state from {:?}", file_path))?;

        Ok(Some(state))
    }

    /// Acquire an exclusive lock on the session state file.
    /// This blocks until the lock is acquired.
    pub fn lock(&self, session_id: &str) -> Result<SessionLock> {
        if !self.storage_dir.exists() {
            fs::create_dir_all(&self.storage_dir)?;
        }
        let file_path = self.get_file_path(session_id);

        // Open or create the file
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&file_path)
            .with_context(|| format!("Failed to open lock file: {:?}", file_path))?;

        // Apply exclusive lock
        file.lock_exclusive()
            .with_context(|| format!("Failed to acquire flock on {:?}", file_path))?;

        Ok(SessionLock { file })
    }

    fn get_file_path(&self, session_id: &str) -> PathBuf {
        // Sanitize session_id to prevent path traversal
        let safe_id = session_id
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>();
        self.storage_dir.join(format!("{}.json", safe_id))
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
