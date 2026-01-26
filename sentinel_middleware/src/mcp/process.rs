use tokio::process::{Child, Command};
use std::process::Stdio; // Stdio is still from std, usually, or tokio re-exports it? tokio::process::Command::stdin takes std::process::Stdio.
use anyhow::{Result, Context};
use tracing::info;

// #[cfg(windows)]
// use win32job::{JobObject, ExtendedLimitInfo};

pub struct ProcessSupervisor {
    // #[cfg(windows)]
    // job: JobObject,
    pub child: Child,
}

impl ProcessSupervisor {
    pub fn spawn(cmd: &str, args: &[String]) -> Result<Self> {
        info!("Spawning upstream tool: {} {:?}", cmd, args);

        /*
        #[cfg(windows)]
        let job = {
            let mut job = JobObject::new().map_err(|e| anyhow::anyhow!("Failed to create Job Object: {}", e))?;
            let mut limits = ExtendedLimitInfo::new();
            limits.limit_kill_on_job_close();
            job.set_extended_limit_info(&mut limits).map_err(|e| anyhow::anyhow!("Failed to set job limits: {}", e))?;
            job
        };
        */

        let child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()) // Capture stderr for logging
            .spawn()
            .context("Failed to spawn upstream tool process")?;

        /*
        #[cfg(windows)]
        // We need to get the raw handle from tokio::process::Child
        // On windows, tokio Child implements AsRawHandle? 
        // Or we might need child.raw_handle() if available.
        // For now, win32job is commented out, so we are safe.
        // job.assign_process(&child).map_err(|e| anyhow::anyhow!("Failed to assign process to job: {}", e))?;
        */

        Ok(Self {
            // #[cfg(windows)]
            // job,
            child,
        })
    }

    pub async fn kill(&mut self) -> Result<()> {
        self.child.kill().await.context("Failed to kill child process")?;
        Ok(())
    }
}
