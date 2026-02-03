use anyhow::Result;
use std::path::PathBuf;
use crate::mcp::sandbox::{SandboxProfile, SandboxPolicy};

/// A profile for running Python in a typical venv or conda env.
/// Grants access to standard library and site-packages locations WITHOUT introspection.
pub struct PythonProfile {
    pub env_root: PathBuf,
    pub core_root: Option<PathBuf>,
}

impl PythonProfile {
    pub fn new(env_root: impl Into<PathBuf>, core_root: Option<PathBuf>) -> Self {
        Self {
            env_root: env_root.into(),
            core_root,
        }
    }
}

impl SandboxProfile for PythonProfile {
    fn apply(&self, policy: &mut SandboxPolicy) -> Result<()> {
        let root = &self.env_root;
        
        // 1. The root itself (often needed for venv config)
        policy.read_paths.push(root.clone());
        
        // 2. Core Python (if provided separately, e.g. for venvs pointing to global python)
        if let Some(core) = &self.core_root {
            policy.read_paths.push(core.clone());
        }
        
        // 3. Scripts/bin (executables)
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
        }

        // 4. Common Python Environment Variables (Help avoid registry lookups)
        let python_envs = vec![
            "PYTHONHOME", 
            "PYTHONPATH", 
            "PYTHONUNBUFFERED", 
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONIOENCODING"
        ];
        for env in python_envs {
            if !policy.allow_env.contains(&env.to_string()) {
                policy.allow_env.push(env.to_string());
            }
        }
        
        Ok(())
    }
}
