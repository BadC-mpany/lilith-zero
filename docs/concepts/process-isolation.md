# Process Isolation & Sandboxing

**Lilith Zero** implements rigorous, OS-specific mechanisms to ensure that tool compliance is not just a suggestion, but a kernel-enforced law.

## Windows: Job Objects & AppContainers

On Windows, we utilize a multi-tiered defense strategy.

### Tier 1: Job Objects
Every tool spawned by Lilith Zero is assigned to a [Windows Job Object](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

-   **Lifecycle Management**: The `JOBOBJECT_LIMIT_KILL_ON_JOB_CLOSE` flag ensures that if the Lilith Zero middleware crashes or is killed, Windows **immediately** terminates all child processes. No zombies, ever.
-   **Resource Limits**: We apply strict memory and CPU time limits on the Job Object.

### Tier 2: Restricted Tokens
We do not run tools with the user's full main token. Instead, we generate a **Restricted Token**:

-   **SID Filtering**: We strip sensitive group memberships (e.g., Administrators).
-   **Privilege Stripping**: We remove privileges like `SeDebugPrivilege` or `SeImpersonatePrivilege`.
-   **Integrity Level**: We can lower the process integrity level to `Low ` or `Untrusted`.

### Tier 3: AppContainers (Experimental)
For maximum security, we support launching tools inside [AppContainers](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)—the same sandbox technology used by UWP apps and Edge. This provides:
-   **Network Isolation**: Blocked by default.
-   **Filesystem Virtualization**: Writes are redirected to a virtual store.

## macOS: The Re-Exec Supervisor

macOS lacks Windows' robust Job Objects, and standard `process_group` signaling is unreliable (tools can detach).

To solve this, Lilith Zero implements the **Re-Exec Supervisor Pattern**:

1.  **Self-Spawn**: When you ask Lilith Zero to run a tool, it actually spawns a copy of *itself* in a special `__supervisor` mode.
2.  **Kqueue Monitoring**: This supervisor process uses `kqueue` EVFILT_PROC to monitor the *parent* (the middleware) and the *child* (the tool).
3.  **Guaranteed Termination**: If the parent process vanishes (crash or kill), the `kqueue` event fires instantly, and the supervisor explicitly `SIGKILL`s the tool before exiting itself.

## Linux: PR_SET_PDEATHSIG

On Linux, we utilize the kernel's `prctl` interface.
-   **PDEATHSIG**: We set `PR_SET_PDEATHSIG` to sends `SIGKILL` to the child process immediately if the parent process thread exits.
-   **Namespaces**: (Planned) Verification using `unshare` to run tools in separate user/mount/network namespaces.
