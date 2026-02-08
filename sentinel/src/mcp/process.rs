//! Upstream process management with Zombie Process Protection.
//!
//! Implements strict parent-child binding to ensure upstream tools are eliminated
//! if the Sentinel middleware crashes or is terminated.

use crate::mcp::pipeline::UpstreamEvent;
use std::process::Stdio;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

// Windows-specific imports
#[cfg(windows)]
use win32job::Job;

// Unix-specific imports
#[cfg(unix)]
use std::os::unix::process::CommandExt;

pub struct ProcessSupervisor {
    // Channel to trigger manual kill
    kill_tx: Option<oneshot::Sender<()>>,
    // Keep job object alive (Windows only)
    #[cfg(windows)]
    _job: Option<Job>,
}

pub type ProcessSpawnResult = (
    ProcessSupervisor,
    Option<Box<dyn AsyncWrite + Unpin + Send>>,
    Option<Box<dyn AsyncRead + Unpin + Send>>,
    Option<Box<dyn AsyncRead + Unpin + Send>>,
);

impl ProcessSupervisor {
    pub fn spawn(
        cmd: &str,
        args: &[String],
        tx_events: mpsc::Sender<UpstreamEvent>,
    ) -> Result<ProcessSpawnResult, crate::core::errors::InterceptorError> {
        debug!("ProcessSupervisor: spawning '{}' with args {:?}", cmd, args);

        let mut command = Command::new(cmd);
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // ------------------------------------------------------------------
        // UNIX: PR_SET_PDEATHSIG
        // ------------------------------------------------------------------
        #[cfg(unix)]
        unsafe {
            command.pre_exec(|| {
                // Send SIGKILL to child if parent (Sentinel) dies
                let ret = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        // ------------------------------------------------------------------
        // WINDOWS: Job Objects (Part 1 - Creation)
        // ------------------------------------------------------------------
        #[cfg(windows)]
        let job = {
            let job = Job::create().map_err(|e| {
                crate::core::errors::InterceptorError::ProcessError(format!(
                    "Failed to create Job Object: {}",
                    e
                ))
            })?;
            let mut info = job.query_extended_limit_info().map_err(|e| {
                crate::core::errors::InterceptorError::ProcessError(format!(
                    "Failed to query job info: {}",
                    e
                ))
            })?;
            info.limit_kill_on_job_close();
            job.set_extended_limit_info(&mut info).map_err(|e| {
                crate::core::errors::InterceptorError::ProcessError(format!(
                    "Failed to set job limits: {}",
                    e
                ))
            })?;
            debug!("Initialized Windows Job Object for automatic cleanup");
            Some(job)
        };

        // Note: On Windows, we need to creation_flags(CREATE_SUSPENDED) if we wanted to
        // strictly ensure assignment before execution, but Job Object assignment works
        // on the handle immediately after spawn, which is usually sufficient for "crash protection".
        // To be strictly atomic (preventing runaway if assignment fails), we'd use suspended.
        // For Sentinel v0.1 simplification, we assign immediately after.

        // Spawn
        let mut child = command.spawn().map_err(|e| {
            crate::core::errors::InterceptorError::ProcessError(format!(
                "Failed to spawn upstream process: {}",
                e
            ))
        })?;

        // ------------------------------------------------------------------
        // WINDOWS: Job Objects (Part 2 - Assignment)
        // ------------------------------------------------------------------
        #[cfg(windows)]
        if let Some(ref job) = job {
            // Safety: We are using the raw handle from the standard library Child
            if let Some(handle) = child.raw_handle() {
                job.assign_process(handle as isize).map_err(|e| {
                    crate::core::errors::InterceptorError::ProcessError(format!(
                        "Failed to assign process to Job Object: {}",
                        e
                    ))
                })?;
                debug!("Assigned process {} to Job Object", child.id().unwrap_or(0));
            }
        }

        let stdin = child
            .stdin
            .take()
            .map(|s| Box::new(s) as Box<dyn AsyncWrite + Unpin + Send>);
        let stdout = child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn AsyncRead + Unpin + Send>);
        let stderr = child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn AsyncRead + Unpin + Send>);

        let (kill_tx, kill_rx) = oneshot::channel();

        tokio::spawn(async move {
            tokio::select! {
                _ = kill_rx => {
                    let _ = child.kill().await;
                }
                status = child.wait() => {
                    match status {
                        Ok(s) => {
                            let _ = tx_events.send(UpstreamEvent::Terminated(s.code())).await;
                        }
                        Err(_) => {
                            let _ = tx_events.send(UpstreamEvent::Terminated(None)).await;
                        }
                    }
                }
            }
        });

        Ok((
            Self {
                kill_tx: Some(kill_tx),
                #[cfg(windows)]
                _job: job,
            },
            stdin,
            stdout,
            stderr,
        ))
    }

    pub fn kill(&mut self) {
        if let Some(tx) = self.kill_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for ProcessSupervisor {
    fn drop(&mut self) {
        self.kill();
        // On Windows, _job is dropped here, which triggers LIMIT_KILL_ON_JOB_CLOSE
        // if the process is still running.
    }
}
