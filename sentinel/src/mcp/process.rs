//! Upstream process management.

use anyhow::Result;
use std::process::Stdio;
use tokio::process::Command;

#[cfg(windows)]
use win32job::{ExtendedLimitInfo, Job};

use tokio::io::{AsyncRead, AsyncWrite};
use crate::mcp::sandbox::ChildProcess;
use crate::mcp::pipeline::UpstreamEvent;
use tokio::sync::{mpsc, oneshot};

pub struct ChildHandle(Box<dyn ChildProcess>);

impl ChildHandle {
    pub async fn kill(&mut self) -> Result<()> {
        self.0.kill().await
    }
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        self.0.wait().await
    }
}

/// Implement ChildProcess for standard Tokio processes.
#[async_trait::async_trait]
impl ChildProcess for tokio::process::Child {
    async fn kill(&mut self) -> Result<()> {
        tokio::process::Child::kill(self).await.map_err(|e| anyhow::anyhow!("Kill failed: {}", e))
    }
    fn start_kill(&mut self) -> Result<()> {
        tokio::process::Child::start_kill(self).map_err(|e| anyhow::anyhow!("Start kill failed: {}", e))
    }
    async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        tokio::process::Child::wait(self).await.map_err(|e| anyhow::anyhow!("Wait failed: {}", e))
    }
    fn id(&self) -> Option<u32> {
        self.id()
    }
}

pub struct ProcessSupervisor {
    #[cfg(windows)]
    #[allow(dead_code)]
    job: Job,
    
    // Channel to trigger manual kill
    kill_tx: Option<oneshot::Sender<()>>,
}

pub type ProcessSpawnResult = (
    ProcessSupervisor,
    Option<Box<dyn AsyncWrite + Unpin + Send>>,
    Option<Box<dyn AsyncRead + Unpin + Send>>,
    Option<Box<dyn AsyncRead + Unpin + Send>>
);

impl ProcessSupervisor {
    pub fn spawn(
        cmd: &str, 
        args: &[String], 
        policy: Option<crate::mcp::sandbox::SandboxPolicy>,
        tx_events: mpsc::Sender<UpstreamEvent>,
    ) -> Result<ProcessSpawnResult> {
        
        let (child_handle, stdin, stdout, stderr) = if let Some(pol) = policy {
            #[cfg(windows)]
            {
                let (ch, si, so, se) = crate::mcp::sandbox::windows::spawn_custom(cmd, args, &pol)?;
                (ChildHandle(ch), si, so, se)
            }
            #[cfg(not(windows))]
            {
                let mut command = Command::new(cmd);
                command.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
                let mut child = command.spawn()?;
                let stdin = child.stdin.take().map(|s| Box::new(s) as Box<dyn AsyncWrite + Unpin + Send>);
                let stdout = child.stdout.take().map(|s| Box::new(s) as Box<dyn AsyncRead + Unpin + Send>);
                let stderr = child.stderr.take().map(|s| Box::new(s) as Box<dyn AsyncRead + Unpin + Send>);
                (ChildHandle(Box::new(child)), stdin, stdout, stderr)
            }
        } else {
            let mut command = Command::new(cmd);
            command.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut child = command.spawn()?;
            let stdin = child.stdin.take().map(|s| Box::new(s) as Box<dyn AsyncWrite + Unpin + Send>);
            let stdout = child.stdout.take().map(|s| Box::new(s) as Box<dyn AsyncRead + Unpin + Send>);
            let stderr = child.stderr.take().map(|s| Box::new(s) as Box<dyn AsyncRead + Unpin + Send>);
            (ChildHandle(Box::new(child)), stdin, stdout, stderr)
        };

        #[cfg(windows)]
        let job = {
            let job = win32job::Job::create().map_err(|e| anyhow::anyhow!("Job create failed: {}", e))?;
            let mut limits = ExtendedLimitInfo::new();
            limits.limit_kill_on_job_close();
            job.set_extended_limit_info(&limits).map_err(|e| anyhow::anyhow!("Job limits failed: {}", e))?;
            job
        };

        let (kill_tx, kill_rx) = oneshot::channel();
        let mut child = child_handle;
        
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
                #[cfg(windows)]
                job,
                kill_tx: Some(kill_tx)
            },
            stdin,
            stdout,
            stderr
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
    }
}
