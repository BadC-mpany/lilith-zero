# Process Supervision & Lifecycle Management

**Lilith Zero** implements rigorous, OS-specific mechanisms to ensure that tool compliance is not just a suggestion, but a kernel-enforced law.

## Windows: Job Objects

On Windows, we utilize **Job Objects** for strict lifecycle management.

### Job Objects
Every tool spawned by Lilith Zero is assigned to a [Windows Job Object](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

-   **Lifecycle Management**: The `JOBOBJECT_LIMIT_KILL_ON_JOB_CLOSE` flag ensures that if the Lilith Zero middleware crashes or is killed, Windows **immediately** terminates all child processes. No zombies, ever.
-   **Resource Limits**: We apply strict memory and CPU time limits on the Job Object.

## macOS: The Re-Exec Supervisor

macOS lacks Windows' robust Job Objects, and standard `process_group` signaling is unreliable (tools can detach).

To solve this, Lilith Zero implements the **Re-Exec Supervisor Pattern**:

1.  **Self-Spawn**: When you ask Lilith Zero to run a tool, it actually spawns a copy of *itself* in a special `__supervisor` mode.
2.  **Kqueue Monitoring**: This supervisor process uses `kqueue` EVFILT_PROC to monitor the *parent* (the middleware) and the *child* (the tool).
3.  **Guaranteed Termination**: If the parent process vanishes (crash or kill), the `kqueue` event fires instantly, and the supervisor explicitly `SIGKILL`s the tool before exiting itself.

## Linux: PR_SET_PDEATHSIG

On Linux, we utilize the kernel's `prctl` interface.
-   **PDEATHSIG**: We set `PR_SET_PDEATHSIG` to sends `SIGKILL` to the child process immediately if the parent process thread exits.
