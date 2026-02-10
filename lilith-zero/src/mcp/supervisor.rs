// Copyright 2026 BadCompany
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Supervisor process for macOS to handle zombie protection.
//!
//! This module implements a "Re-Exec" supervisor pattern. The main lilith-zero process
//! spawns a copy of itself in this mode to wrap the upstream tool.
//! This allows us to use kqueue to monitor the parent (Main) process safely without
//! invoking UB in a pre_exec hook.

#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use tokio::process::Command;
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

#[cfg(target_os = "macos")]
use libc;

/// Entry point for the supervisor process.
pub async fn supervisor_main(
    parent_pid: u32,
    cmd: String,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(unix))]
    {
        let _ = parent_pid;
        let _ = cmd;
        let _ = args;
        Err("Supervisor mode not supported on non-Unix platforms".into())
    }

    #[cfg(unix)]
    {
        eprintln!(
            "[supervisor] Starting for parent {} wrapping '{}'",
            parent_pid, cmd
        );

        // 1. Spawn the child process (Upstream Tool)
        let mut child = Command::new(&cmd)
            .args(&args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        // 2. Set up Parent Monitoring
        #[cfg(target_os = "macos")]
        let parent_died = monitor_parent_kqueue(parent_pid as i32)?;

        #[cfg(not(target_os = "macos"))]
        let parent_died = std::future::pending::<()>();

        // 3. Set up Signal Forwarding
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        // 4. Main Loop
        tokio::select! {
            _ = parent_died => {
                eprintln!("[supervisor] Parent died! Killing child...");
                let _ = child.kill().await;
                std::process::exit(1);
            }
            status = child.wait() => {
                match status {
                    Ok(s) => {
                         std::process::exit(s.code().unwrap_or(1));
                    }
                    Err(e) => {
                        eprintln!("[supervisor] Child wait failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            _ = sigterm.recv() => {
                let _ = child.kill().await;
            }
            _ = sigint.recv() => {
                let _ = child.kill().await;
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn monitor_parent_kqueue(
    pid: i32,
) -> Result<impl std::future::Future<Output = ()>, std::io::Error> {
    // We need to run kqueue in a way that is awaitable.
    // Since kqueue is blocking, we can spawn a blocking task.

    // Safety: calling kqueue/kevent is safe in a fresh process.

    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let event = unsafe {
        libc::kevent {
            ident: pid as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        }
    };

    let ret = unsafe { libc::kevent(kq, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) };

    if ret < 0 {
        unsafe { libc::close(kq) };
        return Err(std::io::Error::last_os_error());
    }

    Ok(async move {
        let _ = tokio::task::spawn_blocking(move || {
            let mut events = unsafe {
                [libc::kevent {
                    ident: 0,
                    filter: 0,
                    flags: 0,
                    fflags: 0,
                    data: 0,
                    udata: std::ptr::null_mut(),
                }]
            };

            // This blocks until parent exits
            let n = unsafe {
                libc::kevent(
                    kq,
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    1,
                    std::ptr::null(),
                )
            };

            unsafe { libc::close(kq) };

            if n > 0 {
                return; // Triggered
            }
        })
        .await;
    })
}
