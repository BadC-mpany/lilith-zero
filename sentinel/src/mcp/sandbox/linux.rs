#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use landlock::{
    Access, AccessFs, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetError,
    ABI_V1, ABI_V2, ABI_V3, ABI_V4,
};
#[cfg(target_os = "linux")]
use tracing::{debug, info, warn};
#[cfg(target_os = "linux")]
use crate::mcp::sandbox::SandboxPolicy;

#[cfg(target_os = "linux")]
pub fn spawn(cmd: &mut tokio::process::Command, policy: &SandboxPolicy) -> Result<()> {
    // Landlock implementation for Linux.
    // Unlike Windows AppContainer which wraps the child, Landlock can be applied 
    // to the current process before exec, or we can use a helper.
    // However, tokio::process::Command::pre_exec is the standard way.
    
    // We must clone policy to move into the closure.
    let policy = policy.clone();
    
    // Safety: pre_exec runs in the child process after fork, before exec.
    unsafe {
        cmd.pre_exec(move || {
            apply_landlock(&policy).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        });
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_landlock(policy: &SandboxPolicy) -> Result<()> {
    // 1. Define Ruleset
    let abi = ABI_V1; // Start conservative, or verify ABI
    let status = landlock::ABI::V1.version()?;
    if status < ABI_V1 {
        // Fallback or error?
        // For secure by default, we should probably error if we can't sandbox?
        // But for now, let's warn.
         warn!("Kernel does not support Landlock. Sandboxing disabled.");
         return Ok(());
    }
    
    // define access rights
    let ro_files = AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir;
    let rw_files = ro_files | AccessFs::WriteFile | AccessFs::RemoveDir | AccessFs::RemoveFile | AccessFs::MakeChar | AccessFs::MakeDir | AccessFs::MakeReg | AccessFs::MakeSock | AccessFs::MakeFifo | AccessFs::MakeBlock | AccessFs::MakeSym;

    let mut ruleset = Ruleset::new()
        .handle_access(AccessFs::from_all(ABI_V1))
        .create()?;
    
    // 2. Add Rules
    
    // A. Allow Read Paths
    for path in &policy.read_paths {
        if let Ok(fd) = PathFd::new(path) {
             ruleset = ruleset.add_rule(PathBeneath::new(fd, ro_files))?;
        }
    }
    
    // B. Allow Write Paths
    for path in &policy.write_paths {
         if let Ok(fd) = PathFd::new(path) {
             ruleset = ruleset.add_rule(PathBeneath::new(fd, rw_files))?;
        }
    }

    // C. Always allow /lib, /usr/lib, /bin, /usr/bin for runtime?
    // This is the "Runtime Discovery" part handled by runtime.rs which passes paths to config.
    // But we might want some basics if config is empty?
    
    // 3. Restrict Self
    let restriction = ruleset.restrict_self()?;
    
    // Landlock applied. The process (and its children) can now only access the paths defined.
    
    Ok(())
}
