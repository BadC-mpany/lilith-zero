use tokio::process::{Child, Command};
use std::process::Stdio;
use anyhow::{Result, Context};
use tracing::info;

#[cfg(windows)]
use win32job::{JobObject, ExtendedLimitInfo, JobInformationLimit};

pub struct ProcessSupervisor {
    #[cfg(windows)]
    job: JobObject,
    pub child: Child,
}

impl ProcessSupervisor {
    pub fn spawn(cmd: &str, args: &[String]) -> Result<Self> {
        info!("Spawning upstream tool: {} {:?}", cmd, args);

        #[cfg(windows)]
        let job = {
            let job = JobObject::new().map_err(|e| anyhow::anyhow!("Failed to create Job Object: {}", e))?;
            let mut limits = ExtendedLimitInfo::new();
            limits.limit_kill_on_job_close();
            job.set_extended_limit_info(&mut limits).map_err(|e| anyhow::anyhow!("Failed to set job limits: {}", e))?;
            job
        };

        let child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn upstream tool process")?;

        #[cfg(windows)]
        {
             // On Windows, we need to assign the process to the job object.
             // tokio::process::Child doesn't directly expose the raw handle easily in a cross-platform way,
             // but strictly speaking we need std::os::windows::io::AsRawHandle.
             // However, win32job's assign_process takes a handle.
             // Let's use the underlying std child if possible, or assume OS handle is available.
             
             // Workaround: tokio Child has `raw_handle()` if the unstable feature is enabled, 
             // but normally we might need to rely on the fact that we can get the PID or handle.
             
             // Ideally we'd use `child.raw_handle()` but tokio 1.x hides it well.
             // Standard approach: JobObject::assign_process takes &impl AsRawHandle.
             // tokio::process::Child implements AsRawHandle on Windows.
             
             job.assign_process(&child).map_err(|e| anyhow::anyhow!("Failed to assign process to job: {}", e))?;
        }

        Ok(Self {
            #[cfg(windows)]
            job,
            child,
        })
    }

    pub async fn kill(&mut self) -> Result<()> {
        self.child.kill().await.context("Failed to kill child process")?;
        Ok(())
    }
}
