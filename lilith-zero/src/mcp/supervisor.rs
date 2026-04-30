// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use tokio::process::Command;
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use libc;

/// Entry point for the macOS/Linux supervisor sub-process.
///
/// The main process re-execs itself with the `__supervisor` subcommand, passing the
/// parent PID.
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
        // Become a subreaper on Linux so we catch all orphans
        #[cfg(target_os = "linux")]
        // SAFETY: PR_SET_CHILD_SUBREAPER ensures the supervisor process inherits orphaned grandchildren.
        unsafe {
            let _ = libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
        }

        let mut command = Command::new(&cmd);
        command.args(&args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        // Create process group for the actual child command
        // SAFETY: setpgid is safe.
        unsafe {
            command.pre_exec(|| {
                let ret = libc::setpgid(0, 0);
                if ret != 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() != Some(libc::EPERM) {
                        eprintln!("lilith-zero supervisor: setpgid(0,0) failed: {}", err);
                    }
                }
                Ok(())
            });
        }

        let mut child = command.spawn()?;
        let child_pid = child.id().unwrap_or(0) as i32;

        #[cfg(target_os = "macos")]
        let parent_died = monitor_parent_kqueue(parent_pid as i32)?;

        #[cfg(target_os = "linux")]
        let parent_died = async move {
            loop {
                // kill(pid, 0) checks if the process exists
                // SAFETY: We are just checking for process existence, no signals are sent.
                if unsafe { libc::kill(parent_pid as i32, 0) } != 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        };

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let parent_died = std::future::pending::<()>();

        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        let kill_pg = || {
            if child_pid > 0 {
                // SAFETY: sending kill to negative PID (process group)
                unsafe { libc::kill(-child_pid, libc::SIGKILL); }
            }

            #[cfg(target_os = "linux")]
            {
                // Rigorous cleanup: since we are the subreaper, orphaned grandchildren
                // have been reparented to us. Find all processes whose PPID is us, and kill them.
                let my_pid = std::process::id() as i32;
                if let Ok(entries) = std::fs::read_dir("/proc") {
                    for entry in entries.flatten() {
                        if let Ok(file_name) = entry.file_name().into_string() {
                            if let Ok(pid) = file_name.parse::<i32>() {
                                if pid == my_pid || pid == child_pid { continue; }
                                let stat_path = format!("/proc/{}/stat", pid);
                                if let Ok(stat) = std::fs::read_to_string(stat_path) {
                                    let parts: Vec<&str> = stat.split_whitespace().collect();
                                    if parts.len() > 3 {
                                        if let Ok(ppid) = parts[3].parse::<i32>() {
                                            if ppid == my_pid {
                                                // Kill this orphaned descendant's process group just to be safe
                                                // SAFETY: Sending SIGKILL to a process group or a specific PID is safe here as we are cleaning up orphaned children in a supervisor context.
                                                unsafe {
                                                    libc::kill(-pid, libc::SIGKILL);
                                                    libc::kill(pid, libc::SIGKILL);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        tokio::select! {
            _ = parent_died => {
                kill_pg();
                let _ = child.kill().await;
                std::process::exit(1);
            }
            status = child.wait() => {
                match status {
                    Ok(s) => {
                         kill_pg();
                         std::process::exit(s.code().unwrap_or(1));
                    }
                    Err(_) => {
                        kill_pg();
                        std::process::exit(1);
                    }
                }
            }
            _ = sigterm.recv() => {
                kill_pg();
                let _ = child.kill().await;
            }
            _ = sigint.recv() => {
                kill_pg();
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
    // SAFETY: kqueue syscalls operate on kernel-managed file descriptors; no aliasing hazards.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let event = libc::kevent {
        ident: pid as usize,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };

    // SAFETY: kq is a valid file descriptor obtained above; event is fully initialised.
    let ret = unsafe { libc::kevent(kq, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) };

    if ret < 0 {
        // SAFETY: kq is valid.
        unsafe { libc::close(kq) };
        return Err(std::io::Error::last_os_error());
    }

    Ok(async move {
        let _ = tokio::task::spawn_blocking(move || {
            let mut events = [libc::kevent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            }];

            // SAFETY: kq and events are valid; blocking call inside spawn_blocking.
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

            // SAFETY: kq is valid.
            unsafe { libc::close(kq) };

            if n > 0 {}
        })
        .await;
    })
}
