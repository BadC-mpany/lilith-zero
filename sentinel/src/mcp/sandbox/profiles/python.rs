use anyhow::Result;
use std::path::PathBuf;
use crate::mcp::sandbox::{SandboxProfile, SandboxPolicy};

/// A profile for running Python in a typical venv or conda env.
/// Grants access to standard library and site-packages locations WITHOUT introspection.
pub struct PythonProfile {
    pub env_root: PathBuf,
}

impl PythonProfile {
    pub fn new(env_root: impl Into<PathBuf>) -> Self {
        Self {
            env_root: env_root.into(),
        }
    }
}

impl SandboxProfile for PythonProfile {
    fn apply(&self, policy: &mut SandboxPolicy) -> Result<()> {
        let root = &self.env_root;
        
        // 1. The root itself (often needed for venv config)
        policy.read_paths.push(root.clone());
        
        // 2. Scripts/bin (executables)
        if cfg!(windows) {
            policy.read_paths.push(root.join("Scripts"));
            policy.read_paths.push(root.join("Lib"));
            policy.read_paths.push(root.join("DLLs"));
            
            // Site-packages
            let site_packages = root.join("Lib").join("site-packages");
            if site_packages.exists() {
                policy.read_paths.push(site_packages);
            }
        } else {
            policy.read_paths.push(root.join("bin"));
            policy.read_paths.push(root.join("lib"));
            // Modern python often has lib/pythonX.Y/site-packages. 
            // Since we aren't introspecting version, we might need to rely on the user providing a deep enough root 
            // or just allow "lib" which covers it.
        }

        // 3. For Conda specifically, we might need more.
        // But for "Minimal", we strictly trust the input root.
        
        Ok(())
    }
}
