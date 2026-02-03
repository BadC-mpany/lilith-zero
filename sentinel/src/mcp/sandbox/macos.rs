#[cfg(target_os = "macos")]
use anyhow::{Context, Result};
#[cfg(target_os = "macos")]
use rusty_sandbox::Sandbox;
#[cfg(target_os = "macos")]
use tracing::{debug, info};
#[cfg(target_os = "macos")]
use crate::mcp::sandbox::SandboxPolicy;

#[cfg(target_os = "macos")]
pub fn spawn(cmd: &mut tokio::process::Command, policy: &SandboxPolicy) -> Result<()> {
    // On macOS, we can use `sandbox-exec -p PROFILE cmd` pattern or `sandbox_init` in child.
    // Using `pre_exec` with `sandbox_init` is cleaner but `rusty-sandbox` applies to current process.
    
    let policy = policy.clone();
    
    unsafe {
        cmd.pre_exec(move || {
            apply_seatbelt(&policy).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_seatbelt(policy: &SandboxPolicy) -> Result<()> {
    // Construct SBPL profile...
    // But actually, let's stick to rusty-sandbox builder if possible, or simple profile.
    
    let mut sb = Sandbox::new();
    
    for path in &policy.read_paths {
        sb.allow_read_path(path);
    }
    for path in &policy.write_paths {
        sb.allow_write_path(path);
    }
    
    // allow_network handling in rusty-sandbox? 
    // It might default to deny.
    
    // Apply
    sb.apply().map_err(|e| anyhow::anyhow!("Failed to apply seatbelt profile: {}", e))?;
    
    Ok(())
}

