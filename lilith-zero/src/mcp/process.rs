// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use crate::mcp::pipeline::UpstreamEvent;
use std::process::Stdio;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

#[cfg(windows)]
use win32job::Job;

/// Manages the lifecycle of the upstream MCP server subprocess.
///
/// On Linux, uses `PR_SET_PDEATHSIG` to kill the child when the parent exits.
/// On macOS, re-execs as a supervisor process that uses kqueue `NOTE_EXIT` to monitor the parent.
/// On Windows, attaches the child to a Job Object with `KillOnJobClose`.
pub struct ProcessSupervisor {
    kill_tx: Option<oneshot::Sender<()>>,
    #[cfg(windows)]
    _job: Option<Job>,
}

/// Return type of [`ProcessSupervisor::spawn`]: supervisor handle plus stdio streams.
pub type ProcessSpawnResult = (
    ProcessSupervisor,
    Option<Box<dyn AsyncWrite + Unpin + Send>>,
    Option<Box<dyn AsyncRead + Unpin + Send>>,
    Option<Box<dyn AsyncRead + Unpin + Send>>,
);

impl ProcessSupervisor {
    /// Spawn the upstream MCP server process at `cmd` with `args`.
    ///
    /// Returns a [`ProcessSpawnResult`] containing the supervisor handle and the three stdio
    /// streams (stdin, stdout, stderr).  The caller must pass `tx_events` so the supervisor can
    /// deliver [`UpstreamEvent::Terminated`] when the child exits.
    pub fn spawn(
        cmd: &str,
        args: &[String],
        tx_events: mpsc::Sender<UpstreamEvent>,
    ) -> Result<ProcessSpawnResult, crate::engine_core::errors::InterceptorError> {
        debug!("ProcessSupervisor: spawning '{}' with args {:?}", cmd, args);

        #[cfg(target_os = "macos")]
        let mut command = {
            let self_exe = std::env::current_exe().map_err(|e| {
                crate::engine_core::errors::InterceptorError::ProcessError(format!(
                    "Failed to get current executable path: {}",
                    e
                ))
            })?;
            let pid = std::process::id();
            let mut c = Command::new(self_exe);
            c.arg("__supervisor");
            c.arg("--parent-pid");
            c.arg(pid.to_string());
            c.arg("--");
            c.arg(cmd);
            c.args(args);
            c
        };

        #[cfg(not(target_os = "macos"))]
        let mut command = Command::new(cmd);
        #[cfg(not(target_os = "macos"))]
        command.args(args);

        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(unix)]
        // SAFETY: `prctl` and `setpgid` are syscalls with no Rust-visible aliasing hazards.
        unsafe {
            command.pre_exec(|| {
                #[cfg(target_os = "linux")]
                {
                    let ret = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                    if ret != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                
                // Create a new process group for the child (Linux & macOS)
                // This allows the supervisor to send SIGKILL to the entire process group
                // to prevent double-fork daemonization escapes.
                let ret = libc::setpgid(0, 0);
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        #[cfg(windows)]
        let job = {
            let job = Job::create().map_err(|e| {
                crate::engine_core::errors::InterceptorError::ProcessError(format!(
                    "Failed to create Job Object: {}",
                    e
                ))
            })?;
            let mut info = job.query_extended_limit_info().map_err(|e| {
                crate::engine_core::errors::InterceptorError::ProcessError(format!(
                    "Failed to query job info: {}",
                    e
                ))
            })?;
            info.limit_kill_on_job_close();
            job.set_extended_limit_info(&info).map_err(|e| {
                crate::engine_core::errors::InterceptorError::ProcessError(format!(
                    "Failed to set job limits: {}",
                    e
                ))
            })?;
            debug!("Initialized Windows Job Object for automatic cleanup");
            Some(job)
        };

        let mut child = command.spawn().map_err(|e| {
            crate::engine_core::errors::InterceptorError::ProcessError(format!(
                "Failed to spawn upstream process: {}",
                e
            ))
        })?;

        #[cfg(windows)]
        if let Some(ref job) = job {
            if let Some(handle) = child.raw_handle() {
                job.assign_process(handle as isize).map_err(|e| {
                    crate::engine_core::errors::InterceptorError::ProcessError(format!(
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
        
        let pid_opt = child.id();

        tokio::spawn(async move {
            tokio::select! {
                _ = kill_rx => {
                    #[cfg(unix)]
                    if let Some(pid) = pid_opt {
                        // Kill the entire process group
                        // SAFETY: process ID is valid and negative pid means send to process group.
                        unsafe {
                            libc::kill(-(pid as i32), libc::SIGKILL);
                        }
                    }
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

    /// Send a kill signal to the supervised process.
    pub fn kill(&mut self) {
        if let Some(tx) = self.kill_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for ProcessSupervisor {
    fn drop(&mut self) {
        self.kill();
    }
}
