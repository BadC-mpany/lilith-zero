//! Upstream process management.

use anyhow::Result;
use tracing::debug;
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use crate::mcp::pipeline::UpstreamEvent;

pub struct ProcessSupervisor {
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
        tx_events: mpsc::Sender<UpstreamEvent>,
    ) -> Result<ProcessSpawnResult> {
        debug!("ProcessSupervisor: spawning '{}' with args {:?}", cmd, args);
        
        let mut command = Command::new(cmd);
        command.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        
        // Windows-specific creation flags could be added here if needed (e.g. CREATE_NO_WINDOW), 
        // but keeping it simple for now.
        #[cfg(windows)]
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW to hide console window? 
        // actually standard stdio redirection usually hides it if not detached. 
        // keeping it standard.

        let mut child = command.spawn()?;
        
        let stdin = child.stdin.take().map(|s| Box::new(s) as Box<dyn AsyncWrite + Unpin + Send>);
        let stdout = child.stdout.take().map(|s| Box::new(s) as Box<dyn AsyncRead + Unpin + Send>);
        let stderr = child.stderr.take().map(|s| Box::new(s) as Box<dyn AsyncRead + Unpin + Send>);

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
