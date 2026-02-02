//! Upstream process management.
//!
//! This module handles spawning and supervising the upstream MCP server process.
//! On Windows, it uses Job Objects to ensure the child process is terminated
//! if the middleware dies.

use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::{Child, Command};
use tracing::info;

#[cfg(windows)]
use win32job::{ExtendedLimitInfo, Job};

/// Process supervisor that ensures child process lifecycle is bound to parent.
///
/// On Windows: Uses Job Objects with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
/// On Linux: Uses PR_SET_PDEATHSIG to send SIGKILL when parent dies.
///
/// The `job` field is intentionally never read after construction because
/// the Job Object's cleanup happens automatically when it is dropped.
/// Dropping the Job (when ProcessSupervisor is dropped) triggers the
/// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE behavior, terminating all assigned processes.
pub struct ProcessSupervisor {
    /// Windows Job Object handle. Kept alive to maintain process binding.
    /// When dropped, all processes in the job are terminated.
    #[cfg(windows)]
    #[allow(dead_code)]
    job: Job,
    pub child: Child,
}

impl ProcessSupervisor {
    pub fn spawn(cmd: &str, args: &[String]) -> Result<Self> {
        info!("Spawning upstream tool: {} {:?}", cmd, args);

        #[cfg(windows)]
        let job = {
            let job =
                Job::create().map_err(|e| anyhow::anyhow!("Failed to create Job Object: {}", e))?;
            let mut limits = ExtendedLimitInfo::new();
            limits.limit_kill_on_job_close();
            job.set_extended_limit_info(&limits)
                .map_err(|e| anyhow::anyhow!("Failed to set job limits: {}", e))?;
            job
        };

        #[cfg(unix)]
        let child = {
            // On Unix, use pre_exec to set PR_SET_PDEATHSIG before exec
            // This ensures the child receives SIGKILL if the parent dies
            // On Unix, use pre_exec to set PR_SET_PDEATHSIG before exec
            // This ensures the child receives SIGKILL if the parent dies
            // SAFETY:
            // 1. `pre_exec` runs in the child process after `fork` but before `exec`.
            //    It is critical that only async-signal-safe functions are called here.
            //    `libc::prctl` is a direct syscall wrapper and is generally considered safe for this use.
            // 2. We use `PR_SET_PDEATHSIG` with `SIGKILL` to ensure the child is ruthlessly terminated
            //    if the parent (Sentinel) crashes or exits. This is a core security invariant for
            //    process binding.
            unsafe {
                Command::new(cmd)
                    .args(args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .pre_exec(|| {
                        // PR_SET_PDEATHSIG = 1, SIGKILL = 9
                        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                        Ok(())
                    })
                    .spawn()
                    .context("Failed to spawn upstream tool process")?
            }
        };

        #[cfg(windows)]
        let child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn upstream tool process")?;

        #[cfg(windows)]
        {
            // Assign process to job object for lifecycle binding
            if let Some(h) = child.raw_handle() {
                let handle = h as isize;
                job.assign_process(handle)
                    .map_err(|e| anyhow::anyhow!("Failed to assign process to job: {}", e))?;
            }
        }

        Ok(Self {
            #[cfg(windows)]
            job,
            child,
        })
    }

    pub async fn kill(&mut self) -> Result<()> {
        self.child
            .kill()
            .await
            .context("Failed to kill child process")?;
        Ok(())
    }
}

impl Drop for ProcessSupervisor {
    fn drop(&mut self) {
        // Best effort cleanup.
        // On Windows, Job Object handles it.
        // On Unix, PR_SET_PDEATHSIG handles parent death.
        // But for explicit drops (restarts), we try to kill.
        
        let _ = self.child.start_kill(); 
        
        #[cfg(unix)]
        {
            if let Some(id) = self.child.id() {
                // SAFETY:
                // 1. the pid is obtained from the child object which we own, so it's likely valid.
                // 2. libc::kill is a syscall. Sending SIGKILL is safe from memory perspective.
                // 3. We ignore errors because if the process is already dead, our job is done.
                // 4. This is a best-effort fallback if the OS-level binding failed.
                unsafe {
                   libc::kill(id as i32, libc::SIGKILL);
                }
            }
        }
    }
}
