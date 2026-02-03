use anyhow::Result;
use std::path::PathBuf;

pub mod windows;
// pub mod runtime; // DELETED - Legacy Magic
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

pub mod profiles;

/// The explicit security policy for a sandbox.
/// Start with defaults (all denied) and explicitly grant permissions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct SandboxPolicy {
    /// Allow network access (all or nothing for now).
    #[serde(default)]
    pub allow_network: bool,
    
    /// List of paths the sandboxed process is allowed to read.
    #[serde(default)]
    pub read_paths: Vec<PathBuf>,
    
    /// List of paths the sandboxed process is allowed to write.
    #[serde(default)]
    pub write_paths: Vec<PathBuf>,
    
    /// List of allowed environment variables. If empty, NONE are allowed (except minimal system ones).
    #[serde(default)]
    pub allow_env: Vec<String>,
}

impl SandboxPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_paths.push(path.into());
        self
    }
    
    pub fn allow_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.write_paths.push(path.into());
        self
    }
    
    pub fn allow_network(mut self, allow: bool) -> Self {
        self.allow_network = allow;
        self
    }
}

/// A Sandbox Profile knows how to configure a Policy for a specific runtime/tool.
pub trait SandboxProfile {
    fn apply(&self, policy: &mut SandboxPolicy) -> Result<()>;
}

