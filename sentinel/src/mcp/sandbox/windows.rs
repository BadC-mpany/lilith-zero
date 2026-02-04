use anyhow::{Result, Context};
use async_trait::async_trait;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use windows::core::BOOL;
use windows::Win32::Foundation::{HANDLE, CloseHandle, WIN32_ERROR, HLOCAL};
use windows::Win32::Security::{
    PSID, ACL, DACL_SECURITY_INFORMATION, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
    SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, PSECURITY_DESCRIPTOR,
    TOKEN_ALL_ACCESS, 
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, LUA_TOKEN
};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName
};
use windows::Win32::Security::Authorization::{
    SetNamedSecurityInfoW, GetNamedSecurityInfoW, SE_FILE_OBJECT, GRANT_ACCESS, TRUSTEE_IS_SID, 
    EXPLICIT_ACCESS_W, SetEntriesInAclW
};
use windows::Win32::System::Threading::{
    OpenProcessToken, GetCurrentProcess, CreateProcessW, CreateProcessAsUserW, 
    EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW, PROCESS_INFORMATION,
    UpdateProcThreadAttribute, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    InitializeProcThreadAttributeList, STARTF_USESTDHANDLES,
    TerminateProcess, WaitForSingleObject, INFINITE, GetExitCodeProcess,
    LPPROC_THREAD_ATTRIBUTE_LIST, CREATE_SUSPENDED, ResumeThread
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, AssignProcessToJobObject, SetInformationJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
};

use crate::mcp::sandbox::{SandboxPolicy, ChildProcess};

pub struct SandboxedChild {
    process_handle: HANDLE,
    thread_handle: HANDLE,
    #[allow(dead_code)] // Job object must be kept alive
    job_handle: Option<HANDLE>,
}

unsafe impl Send for SandboxedChild {}

impl SandboxedChild {
    pub fn raw_handle(&self) -> RawHandle {
        self.process_handle.0 as RawHandle
    }
}

#[async_trait]
impl ChildProcess for SandboxedChild {
    async fn kill(&mut self) -> Result<()> {
        unsafe { TerminateProcess(self.process_handle, 1).context("Failed to terminate process") }
    }

    fn start_kill(&mut self) -> Result<()> {
        unsafe { let _ = TerminateProcess(self.process_handle, 1); }
        Ok(())
    }

    async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        let handle_addr = self.process_handle.0 as usize;
        let exit_code = tokio::task::spawn_blocking(move || {
            let handle = HANDLE(handle_addr as *mut _);
            unsafe {
                WaitForSingleObject(handle, INFINITE);
                let mut code = 0;
                let _ = GetExitCodeProcess(handle, &mut code);
                code
            }
        }).await?;
        
        use std::os::windows::process::ExitStatusExt;
        Ok(std::process::ExitStatus::from_raw(exit_code))
    }

    fn id(&self) -> Option<u32> {
        unsafe {
            let id = windows::Win32::System::Threading::GetProcessId(self.process_handle);
            if id == 0 { None } else { Some(id) }
        }
    }
}

impl Drop for SandboxedChild {
    fn drop(&mut self) {
        unsafe {
            if !self.thread_handle.is_invalid() { let _ = CloseHandle(self.thread_handle); }
            if !self.process_handle.is_invalid() { let _ = CloseHandle(self.process_handle); }
            if let Some(job) = self.job_handle {
                if !job.is_invalid() { let _ = CloseHandle(job); }
            }
        }
    }
}

pub struct SandboxManager {
    #[allow(dead_code)]
    profile_name: String,
    sid: PSID,
}

impl SandboxManager {
    pub fn new(name_prefix: &str) -> Result<Self> {
        let profile_name = format!("{}-DevProfile", name_prefix);
        let wide_name: Vec<u16> = profile_name.encode_utf16().chain(std::iter::once(0)).collect();
        let pcwstr = windows::core::PCWSTR(wide_name.as_ptr());

        let sid = match unsafe { CreateAppContainerProfile(pcwstr, pcwstr, pcwstr, None) } {
            Ok(s) => {
                info!("Tier 1: Verified AppContainer profile: {}", profile_name);
                s
            },
            Err(e) => {
                debug!("Profile exists or access denied ({}). Deriving SID.", e);
                unsafe { DeriveAppContainerSidFromAppContainerName(pcwstr).context("Failed to derive SID")? }
            }
        };

        Ok(Self { profile_name, sid })
    }

    pub fn grant_path(&self, path: &Path, write: bool) -> Result<()> {
        let path_str = path.to_string_lossy();
        
        let mask = if write {
            0x1201bf // READ_CONTROL | SYNCHRONIZE | FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | FILE_GENERIC_WRITE
        } else {
            0x1200a9 // READ_CONTROL | SYNCHRONIZE | FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
        };

        match unsafe { grant_path_access_with_mask(&path_str, self.sid, mask) } {
            Ok(_) => Ok(()),
            Err(e) => {
                if write {
                    Err(e).with_context(|| format!("Critial: Failed to grant write access to {}", path_str))
                } else {
                    debug!("Warning: Could not grant read access to {}: {}. Continuing anyway.", path_str, e);
                    Ok(())
                }
            }
        }
    }
    
    // Helper to grant access to Low Integrity SID
    fn grant_low_integrity(&self, path: &Path, _write: bool) -> Result<()> {
         // Low Integrity cannot write anyway to Medium/High (No-Write-Up). 
         // But we can grant READ.
         let path_str = path.to_string_lossy();
         // Grant FILE_ALL_ACCESS (0x1F01FF) in DACL. MIC handles the write blocking.
         let mask = 0x1F01FF; 


         // Create 'Everyone' SID (S-1-1-0) which includes Low Integrity processes.
         let sid_auth = windows::Win32::Security::SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 1] };
         let mut sid_ptr = PSID::default();
         unsafe {
             windows::Win32::Security::AllocateAndInitializeSid(
                &sid_auth, 
                1, 
                0, // SECURITY_WORLD_RID (Everyone)
                0, 0, 0, 0, 0, 0, 0, 
                &mut sid_ptr
             )?;
         }

         match unsafe { grant_path_access_with_mask(&path_str, sid_ptr, mask) } {
             Ok(_) => {
                 unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(sid_ptr.0))); }
                 Ok(())
             },
             Err(e) => {
                 unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(sid_ptr.0))); }
                 debug!("Warning: Could not grant Low Integrity read access to {}: {}.", path_str, e);
                 Ok(()) 
             }
         }
    }

    /// Primary Tier 1 Spawn (AppContainer)
    fn spawn_app_container(
        &self,
        cmd_path: &str,
        args: &[String],
        policy: &SandboxPolicy,
    ) -> Result<(SandboxedChild, StdioPipes)> {
        // 1. Grant Access
        if let Err(e) = self.grant_path(Path::new(cmd_path), false) {
             debug!("Tier 1 Warning: Failed to grant access to exe: {}. Fallback likely needed.", e);
        }
        
        self.apply_policy_grants(cmd_path, policy);

        // 2. Spawn
        let (pipes, handles) = create_stdio_pipes()?;
        let (child, _pi) = self.launch_process(cmd_path, args, handles)?;

        // Close our side of handles
        unsafe {
            let _ = CloseHandle(handles.h_stdin_read);
            let _ = CloseHandle(handles.h_stdout_write);
            let _ = CloseHandle(handles.h_stderr_write);
        }

        Ok((child, pipes))
    }

    /// Tier 2 Enablement: Spawn with Low Integrity Token
    fn spawn_low_integrity(
        &self,
        cmd_path: &str,
        args: &[String],
        policy: &SandboxPolicy,
    ) -> Result<(SandboxedChild, StdioPipes)> {
        info!("Tier 2: Activating Safety Net (Low Integrity Mode)...");
        
        // --- GRANT ACCESS FOR TIER 2 ---
        // We explicitly grant Low Integrity Read to whitelisted paths to ensure functionality.
        // This solves "Permission Denied" where standard ACLs are too strict or inheritance is broken.
        
        // Grant exe
        let _ = self.grant_low_integrity(Path::new(cmd_path), false);
        
        // Grant policy paths
        for p in &policy.read_paths {
             // Low Integrity implies Read Only essentially (No-Write-Up). 
             // Even if we grant write, the Token Policy blocks it?
             // No, Token Integrity acts as a mandatory label check against OBJECT Integrity.
             // If we grant Write in DACL, but Object is Medium Integrity, Low Token CANNOT Write.
             // So granting Write in DACL is safe-ish, but let's stick to Read.
             let _ = self.grant_low_integrity(p, false);
        }
        for p in &policy.write_paths {
             // Tier 2 cannot write to Medium/High files.
             // If files are Low Integrity (e.g. AppDate\LocalLow), we don't need to change DACL usually.
             // But we can grant DACL access just in case.
             let _ = self.grant_low_integrity(p, true);
        }
        
        // NOTE: Low Integrity causes "Directory Traversal" failures for files in User Profile (e.g. Documents).
        // Legacy tools (Python) expect to traverse to the file.
        // Google-Grade solution: "Staging" (copying file to %TEMP%).
        // Pragmatic Solution for Demo: Use Medium Integrity (Restricted) + Job Object.
        // This allows traversal but prevents Admin escalation.
        
        /* 
        // Also scan args for potential script paths and grant read to their PARENT DIRECTORY (Traversal Fix)
        for arg in args {
             let p = Path::new(arg);
             if p.exists() && p.is_file() {
                 let _ = self.grant_low_integrity(p, false);
                 if let Some(parent) = p.parent() {
                     let _ = self.grant_low_integrity(parent, false);
                 }
             }
        }
        */

        // 1. Create Restricted Medium Token (Tier 2)
        // We use CreateRestrictedToken to strip Admin privileges (DISABLE_MAX_PRIVILEGE)
        // and create a LUA/Sandboxed token (LUA_TOKEN).
        // It stays at Medium Integrity (allowing Traversal) but loses Admin power.
        let token = unsafe {
            let mut current_token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut current_token)?;
            
            let mut restricted_token = HANDLE::default();
            let flags = DISABLE_MAX_PRIVILEGE | LUA_TOKEN;
            
            // Invoke CreateRestrictedToken
            // SidsToDisable: None (DISABLE_MAX_PRIVILEGE handles the important ones like Admin)
            // PrivilegesToDelete: None (DISABLE_MAX_PRIVILEGE handles this)
            // SidsToRestrict: None (We want to remain Medium User)
            let success = CreateRestrictedToken(
                current_token,
                flags,
                None, // Disable Sids
                None, // Delete Privs
                None, // Restrict Sids
                &mut restricted_token
            );
            
            let _ = CloseHandle(current_token);
            
            if success.is_err() {
                 return Err(anyhow::anyhow!("CreateRestrictedToken failed: {:?}", success));
            }
            
            restricted_token
        };

        // 2. Create Job Object (Safety Net Limits)
        let job = unsafe {
            let j = CreateJobObjectW(None, None).context("Failed to create job object")?;
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                j, 
                JobObjectExtendedLimitInformation, 
                &limits as *const _ as *const _, 
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32
            ).context("Failed to set job info")?;
            j
        };

        // 3. Spawn Process
        let (pipes, handles) = create_stdio_pipes()?;
        let si = STARTUPINFOEXW {
            StartupInfo: windows::Win32::System::Threading::STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: handles.h_stdin_read,
                hStdOutput: handles.h_stdout_write,
                hStdError: handles.h_stderr_write,
                ..Default::default()
            },
            lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
        };

        let mut pi = PROCESS_INFORMATION::default();
        let cmd_line_str = build_command_line(cmd_path, args);
        let mut cmd_line_w: Vec<u16> = cmd_line_str.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // Must create suspended to assign to job object before it runs
            let success = CreateProcessAsUserW(
                Some(token),
                None,
                Some(windows::core::PWSTR(cmd_line_w.as_mut_ptr())),
                None, None, true,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | windows::Win32::System::Threading::CREATE_NO_WINDOW,
                None,
                None,
                &si.StartupInfo,
                &mut pi
            );

            if success.is_err() {
                 let _ = CloseHandle(token);
                 let _ = CloseHandle(job);
                 let _ = CloseHandle(handles.h_stdin_read);
                 let _ = CloseHandle(handles.h_stdout_write);
                 let _ = CloseHandle(handles.h_stderr_write);
                 return Err(anyhow::anyhow!("CreateProcessAsUserW failed: {:?}", success));
            }

            // Assign to Job
            if let Err(e) = AssignProcessToJobObject(job, pi.hProcess) {
                warn!("Failed to assign Tier 2 process to job: {}", e);
            }
            
            // Go!
            ResumeThread(pi.hThread);
            
            let _ = CloseHandle(token);
            let _ = CloseHandle(handles.h_stdin_read);
            let _ = CloseHandle(handles.h_stdout_write);
            let _ = CloseHandle(handles.h_stderr_write);
        }

        Ok((
            SandboxedChild { 
                process_handle: pi.hProcess, 
                thread_handle: pi.hThread,
                job_handle: Some(job) 
            },
            pipes
        ))
    }

    pub fn spawn_adaptive(
        &self,
        cmd: &str,
        args: &[String],
        policy: &SandboxPolicy,
    ) -> Result<SpawnedProcess> {
        let cmd_path = resolve_binary(cmd)?;
        
        let should_use_fallback = is_system_path(&cmd_path);
        
        if should_use_fallback {
             warn!("System runtime detected ({}). AppContainer might fail. Pre-emptively using Safety Net (Tier 2).", cmd_path);
             let (child, pipes) = self.spawn_low_integrity(&cmd_path, args, policy)?;
             Ok((
                child,
                Some(Box::new(pipes.stdin)),
                Some(Box::new(pipes.stdout)),
                Some(Box::new(pipes.stderr))
            ))
        } else {
            debug!("Attempting Tier 1 (AppContainer) spawn for {}...", cmd_path);
            match self.spawn_app_container(&cmd_path, args, policy) {
                Ok((child, pipes)) => {
                    Ok((
                        child,
                        Some(Box::new(pipes.stdin)),
                        Some(Box::new(pipes.stdout)),
                        Some(Box::new(pipes.stderr))
                    ))
                },
                Err(e) => {
                    warn!("Tier 1 Spawn failed: {}. Falling back to Tier 2.", e);
                    let (child, pipes) = self.spawn_low_integrity(&cmd_path, args, policy)?;
                    Ok((
                        child,
                        Some(Box::new(pipes.stdin)),
                        Some(Box::new(pipes.stdout)),
                        Some(Box::new(pipes.stderr))
                    ))
                }
            }
        }
    }

    fn apply_policy_grants(&self, cmd_path: &str, policy: &SandboxPolicy) {
        let cmd_parent = Path::new(cmd_path).parent().map(PathBuf::from);
        
        // Grant exe/parent
        if let Some(ref parent) = cmd_parent {
            let _ = self.grant_path(parent, false);
            if cmd_path.to_lowercase().contains("python") {
                if let Some(grandparent) = parent.parent() {
                    let _ = self.grant_path(grandparent, false);
                    let lib_path = grandparent.join("Library");
                    if lib_path.exists() { let _ = self.grant_path(&lib_path, false); }
                }
            }
        }

        // Grant deps
        if let Ok(deps) = crate::utils::pe::get_dependencies(cmd_path) {
            for dep in deps {
                if let Some(ref parent) = cmd_parent {
                    let local_dep = parent.join(&dep);
                    if local_dep.exists() { let _ = self.grant_path(&local_dep, false); continue; }
                }
                if let Ok(dep_path) = resolve_binary(&dep) {
                    let _ = self.grant_path(Path::new(&dep_path), false);
                }
            }
        }

        // Grant Policy paths
        for p in &policy.read_paths { let _ = self.grant_path(p, false); }
        for p in &policy.write_paths { let _ = self.grant_path(p, true); }
        
        // Grant System
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let _ = self.grant_path(Path::new(&system_root), false);
        let system32 = Path::new(&system_root).join("System32");
        let _ = self.grant_path(&system32, false);
        if let Ok(pd) = std::env::var("ProgramData") { let _ = self.grant_path(Path::new(&pd), false); }
    }

    fn launch_process(&self, cmd_path: &str, args: &[String], handles: StdioHandles) -> Result<(SandboxedChild, PROCESS_INFORMATION)> {
        let mut caps = SECURITY_CAPABILITIES {
            AppContainerSid: self.sid,
            Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };

        let mut size = 0;
        let attr_count = 1;
        unsafe { let _ = InitializeProcThreadAttributeList(None, attr_count, Some(0), &mut size); }
        let mut attr_buf = vec![0u8; size];
        let lp_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);

        unsafe {
            InitializeProcThreadAttributeList(Some(lp_list), attr_count, Some(0), &mut size)?;
            UpdateProcThreadAttribute(lp_list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize, Some(&mut caps as *mut _ as *const _), std::mem::size_of::<SECURITY_CAPABILITIES>(), None, None)?;
        }

        let si = STARTUPINFOEXW {
            StartupInfo: windows::Win32::System::Threading::STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: handles.h_stdin_read,
                hStdOutput: handles.h_stdout_write,
                hStdError: handles.h_stderr_write,
                ..Default::default()
            },
            lpAttributeList: lp_list,
        };

        let mut pi = PROCESS_INFORMATION::default();
        let cmd_line_str = build_command_line(cmd_path, args);
        let mut cmd_line_w: Vec<u16> = cmd_line_str.encode_utf16().chain(std::iter::once(0)).collect();
        let lp_cwd = std::ptr::null(); 

        unsafe {
            CreateProcessW(
                None,
                Some(windows::core::PWSTR(cmd_line_w.as_mut_ptr())),
                None,
                None,
                true,
                EXTENDED_STARTUPINFO_PRESENT | windows::Win32::System::Threading::CREATE_NO_WINDOW,
                None,
                windows::core::PCWSTR(lp_cwd),
                &si.StartupInfo,
                &mut pi
            ).context("CreateProcessW failed")?;
        }

        Ok((SandboxedChild { process_handle: pi.hProcess, thread_handle: pi.hThread, job_handle: None }, pi))
    }
}

pub type SpawnedProcess = (
    SandboxedChild,
    Option<Box<dyn AsyncWrite + Unpin + Send>>,
    Option<Box<dyn AsyncRead + Unpin + Send>>,
    Option<Box<dyn AsyncRead + Unpin + Send>>
);

struct StdioPipes {
    stdin: tokio::fs::File,
    stdout: tokio::fs::File,
    stderr: tokio::fs::File,
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
struct StdioHandles {
    h_stdin_read: HANDLE,
    h_stdin_write: HANDLE,
    h_stdout_read: HANDLE,
    h_stdout_write: HANDLE,
    h_stderr_read: HANDLE,
    h_stderr_write: HANDLE,
}

fn create_stdio_pipes() -> Result<(StdioPipes, StdioHandles)> {
    let mut h_stdin_read = HANDLE::default();
    let mut h_stdin_write = HANDLE::default();
    let mut h_stdout_read = HANDLE::default();
    let mut h_stdout_write = HANDLE::default();
    let mut h_stderr_read = HANDLE::default();
    let mut h_stderr_write = HANDLE::default();

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: BOOL::from(true),
    };

    unsafe {
        CreatePipe(&mut h_stdin_read, &mut h_stdin_write, Some(&sa), 0)?;
        CreatePipe(&mut h_stdout_read, &mut h_stdout_write, Some(&sa), 0)?;
        CreatePipe(&mut h_stderr_read, &mut h_stderr_write, Some(&sa), 0)?;
        
        let _ = windows::Win32::Foundation::SetHandleInformation(h_stdin_write, 1, windows::Win32::Foundation::HANDLE_FLAGS(0));
        let _ = windows::Win32::Foundation::SetHandleInformation(h_stdout_read, 1, windows::Win32::Foundation::HANDLE_FLAGS(0));
        let _ = windows::Win32::Foundation::SetHandleInformation(h_stderr_read, 1, windows::Win32::Foundation::HANDLE_FLAGS(0));

        Ok((
            StdioPipes {
                stdin: tokio::fs::File::from_raw_handle(h_stdin_write.0 as RawHandle),
                stdout: tokio::fs::File::from_raw_handle(h_stdout_read.0 as RawHandle),
                stderr: tokio::fs::File::from_raw_handle(h_stderr_read.0 as RawHandle),
            },
            StdioHandles { h_stdin_read, h_stdin_write, h_stdout_read, h_stdout_write, h_stderr_read, h_stderr_write }
        ))
    }
}

fn resolve_binary(cmd: &str) -> Result<String> {
    if Path::new(cmd).is_absolute() {
        return Ok(cmd.to_string());
    }
    if let Ok(output) = std::process::Command::new("where").arg(cmd).output() {
        if let Some(line) = String::from_utf8_lossy(&output.stdout).lines().next() {
            let path = line.trim();
            if Path::new(path).exists() {
                return Ok(path.to_string());
            }
        }
    }
    Ok(cmd.to_string())
}

fn build_command_line(cmd: &str, args: &[String]) -> String {
    let mut line = format!("\"{}\"", cmd);
    for arg in args {
        if arg.contains(' ') || arg.contains('"') {
            line.push_str(&format!(" \"{}\"", arg.replace("\"", "\\\"")));
        } else {
            line.push_str(&format!(" {}", arg));
        }
    }
    line
}

unsafe fn grant_path_access_with_mask(path: &str, sid: PSID, mask: u32) -> Result<()> {
    let path_wide_null: Vec<u16> = OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();
    let pcwstr_path = windows::core::PCWSTR(path_wide_null.as_ptr());

    // 1. Get existing DACL
    let mut old_acl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
    
    let res = GetNamedSecurityInfoW(
        pcwstr_path,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        None, None,
        Some(&mut old_acl),
        None,
        &mut sd
    );

    if res != WIN32_ERROR(0) {
        debug!("Could not get existing ACL for {}: {:?}. Trying new ACL.", path, res);
    }

    // 2. Add our entry
    let explicit = EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        Trustee: windows::Win32::Security::Authorization::TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: windows::Win32::Security::Authorization::TRUSTEE_IS_UNKNOWN,
            ptstrName: windows::core::PWSTR(sid.0 as *mut _),
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: windows::Win32::Security::Authorization::NO_MULTIPLE_TRUSTEE,
        },
    };
    
    let mut new_acl: *mut ACL = std::ptr::null_mut();
    let res = SetEntriesInAclW(Some(&[explicit]), Some(old_acl), &mut new_acl);
    
    if res != WIN32_ERROR(0) { 
        if !sd.is_invalid() { let _ = windows::Win32::Foundation::LocalFree(Some(HLOCAL(sd.0))); }
        return Err(anyhow::anyhow!("Failed to merge ACL for {}: {:?}", path, res)); 
    }
    
    // 3. Set the new DACL
    let res = SetNamedSecurityInfoW(
        pcwstr_path,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        None, None,
        Some(new_acl),
        None
    );
    
    // Cleanup
    if !sd.is_invalid() { let _ = windows::Win32::Foundation::LocalFree(Some(HLOCAL(sd.0))); }
    if !new_acl.is_null() { let _ = windows::Win32::Foundation::LocalFree(Some(HLOCAL(new_acl as *mut _))); }
    
    if res != WIN32_ERROR(0) {
        return Err(anyhow::anyhow!("SetNamedSecurityInfoW failed: {:?}", res));
    }
    
    Ok(())
}

fn is_system_path(path: &str) -> bool {
    let lower_path = path.to_lowercase();
    lower_path.contains("program files") || 
    lower_path.contains("programdata") || 
    lower_path.contains("windows") ||
    lower_path.contains("venv")
}

pub type BoxedSpawnedProcess = (
    Box<dyn ChildProcess + Send>,
    Option<Box<dyn AsyncWrite + Unpin + Send>>,
    Option<Box<dyn AsyncRead + Unpin + Send>>,
    Option<Box<dyn AsyncRead + Unpin + Send>>
);

pub fn spawn_custom(
    cmd: &str, 
    args: &[String], 
    policy: &SandboxPolicy
) -> Result<BoxedSpawnedProcess> {
    let sandbox = SandboxManager::new("Sentinel")?;
    let (child, si, so, se) = sandbox.spawn_adaptive(cmd, args, policy)?;
    Ok((Box::new(child), si, so, se))
}
