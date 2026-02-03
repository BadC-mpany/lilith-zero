//! Upstream process management.
//!
//! This module handles spawning and supervising the upstream MCP server process.
//! On Windows, it uses Job Objects to ensure the child process is terminated
//! if the middleware dies.

use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::{Child, Command};
use tracing::{info, debug};

#[cfg(windows)]
use win32job::{ExtendedLimitInfo, Job};

use tokio::io::{AsyncRead, AsyncWrite};

/// Abstract handle for a child process (standard or sandboxed).
pub enum ChildHandle {
    Tokio(Child),
    #[cfg(windows)]
    Custom(crate::mcp::sandbox::windows::AppContainerChild),
}

impl ChildHandle {
    pub async fn kill(&mut self) -> Result<()> {
        match self {
            Self::Tokio(c) => c.kill().await.context("Failed to kill tokio child"),
            #[cfg(windows)]
            Self::Custom(c) => c.kill().await,
        }
    }

    pub fn start_kill(&mut self) -> Result<()> {
        match self {
            Self::Tokio(c) => c.start_kill().context("Failed to start kill"),
            #[cfg(windows)]
            Self::Custom(c) => c.start_kill(),
        }
    }
    
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        match self {
            Self::Tokio(c) => c.wait().await.context("Failed to wait on tokio child"),
            #[cfg(windows)]
            Self::Custom(c) => c.wait().await,
        }
    }

    #[cfg(unix)]
    pub fn id(&self) -> Option<u32> {
        match self {
            Self::Tokio(c) => c.id(),
        }
    }
}

pub struct ProcessSupervisor {
    #[cfg(windows)]
    #[allow(dead_code)]
    job: Job,
    pub child: ChildHandle,
}

impl ProcessSupervisor {
    /// Spawn a process with optional sandboxing.
    /// Returns the Supervisor (lifecycle manager) and the Stdio streams.
    pub fn spawn(
        cmd: &str, 
        args: &[String], 
        policy: Option<crate::mcp::sandbox::SandboxPolicy>
    ) -> Result<(Self, Option<Box<dyn AsyncWrite + Unpin + Send>>, Option<Box<dyn AsyncRead + Unpin + Send>>, Option<Box<dyn AsyncRead + Unpin + Send>>)> {
        info!("Spawning upstream tool: {} {:?} (Sandboxed: {})", cmd, args, policy.is_some());

        // Check if we need Windows Custom Path
        #[cfg(windows)]
        if let Some(ref pol) = policy {
             // Use Custom AppContainer Spawner
             let (child_handle, stdin, stdout, stderr) = crate::mcp::sandbox::windows::spawn_custom(cmd, args, pol)?;
             
             let job = Job::create().map_err(|e| anyhow::anyhow!("Failed to create Job Object: {}", e))?;
             let mut limits = ExtendedLimitInfo::new();
             limits.limit_kill_on_job_close();
             job.set_extended_limit_info(&limits)?;
             
             // Assign process handle to job
             let raw_handle = child_handle.raw_handle();
             if let Err(e) = job.assign_process(raw_handle as isize) {
                 debug!("Could not assign AppContainer to Job (may already be in one): {}", e);
             }

             return Ok((
                 Self { job, child: ChildHandle::Custom(child_handle) },
                 stdin,
                 stdout,
                 stderr
             ));
        }

        // Standard Tokio Path (Linux, macOS, or Windows non-sandboxed)
        let mut command = Command::new(cmd);
        command.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(_pol) = &policy {
            #[cfg(target_os = "linux")]
            crate::mcp::sandbox::linux::spawn(&mut command, _pol)?;
            
            #[cfg(target_os = "macos")]
            crate::mcp::sandbox::macos::spawn(&mut command, _pol)?;
        }

        #[cfg(unix)]
        unsafe {
            command.pre_exec(|| {
                 #[cfg(target_os = "linux")]
                 libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                 #[cfg(target_os = "macos")]
                 { /* Seatbelt might handle this, or we add generic pdeathsig if available on mac? Mac doesn't strictly have pdeathsig like Linux */ }
                 Ok(())
            });
        }
        
        // Windows Job Object for standard path
        #[cfg(windows)]
        let job = {
             let job = Job::create().context("Failed to create Job")?;
             let mut limits = ExtendedLimitInfo::new();
             limits.limit_kill_on_job_close();
             job.set_extended_limit_info(&limits)?;
             job
        };

        let mut child = command.spawn().context("Failed to spawn upstream tool")?;

        #[cfg(windows)]
        if let Some(h) = child.raw_handle() {
             job.assign_process(h as isize)?;
        }

        let stdin = child.stdin.take().map(|s| Box::new(s) as Box<dyn AsyncWrite + Unpin + Send>);
        let stdout = child.stdout.take().map(|s| Box::new(s) as Box<dyn AsyncRead + Unpin + Send>);
        let stderr = child.stderr.take().map(|s| Box::new(s) as Box<dyn AsyncRead + Unpin + Send>);

        Ok((
            Self {
                #[cfg(windows)]
                job,
                child: ChildHandle::Tokio(child),
            },
            stdin,
            stdout,
            stderr
        ))
    }

    pub async fn kill(&mut self) -> Result<()> {
        self.child.kill().await
    }
}

impl Drop for ProcessSupervisor {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        
        #[cfg(unix)]
        if let Some(id) = self.child.id() {
             unsafe { libc::kill(id as i32, libc::SIGKILL); }
        }
    }
}
