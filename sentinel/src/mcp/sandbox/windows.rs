use anyhow::Result;

use crate::mcp::sandbox::SandboxPolicy; // CHANGED
use windows::Win32::Security::Isolation::{CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName};

use tokio::io::{AsyncRead, AsyncWrite};
use std::os::windows::io::{FromRawHandle, RawHandle};
use windows::Win32::System::Threading::{
    CreateProcessW, EXTENDED_STARTUPINFO_PRESENT, 
    STARTUPINFOEXW, PROCESS_INFORMATION,  
    UpdateProcThreadAttribute, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    InitializeProcThreadAttributeList, STARTF_USESTDHANDLES, DeleteProcThreadAttributeList,
    TerminateProcess, WaitForSingleObject, INFINITE, GetExitCodeProcess,
    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY
};
use windows::Win32::Foundation::{HANDLE, CloseHandle};
use windows::core::BOOL;
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::Security::{PSID, ACL, DACL_SECURITY_INFORMATION, SUB_CONTAINERS_AND_OBJECTS_INHERIT};
use windows::Win32::Security::Authorization::{
    SetNamedSecurityInfoW, SE_FILE_OBJECT, 
    GRANT_ACCESS, TRUSTEE_IS_SID, EXPLICIT_ACCESS_W, 
    SetEntriesInAclW
};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

/// Configuration helper for Windows AppContainers.
pub struct AppContainerContext {
    pub profile_name: String,
    pub sid: PSID,
}

pub struct AppContainerChild {
    process_handle: HANDLE,
    thread_handle: HANDLE,
}

unsafe impl Send for AppContainerChild {}
unsafe impl Sync for AppContainerChild {}

impl AppContainerChild {
    pub fn raw_handle(&self) -> RawHandle {
        self.process_handle.0 as RawHandle
    }

    pub async fn kill(&mut self) -> Result<()> {
        unsafe {
            TerminateProcess(self.process_handle, 1)?;
        }
        Ok(())
    }
    
    pub fn start_kill(&mut self) -> Result<()> {
        unsafe {
            TerminateProcess(self.process_handle, 1)?;
        }
        Ok(())
    }
    
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        let handle_addr = self.process_handle.0 as usize;
        
        let exit_code = tokio::task::spawn_blocking(move || {
            let handle = HANDLE(handle_addr as *mut std::ffi::c_void);
            unsafe { 
                WaitForSingleObject(handle, INFINITE);
                let mut exit_code: u32 = 0;
                let _ = GetExitCodeProcess(handle, &mut exit_code);
                exit_code
            }
        }).await?;
        
        tracing::debug!("Upstream AppContainer process exited with code: {}", exit_code);
        
        #[cfg(unix)]
        { Ok(std::process::ExitStatus::default()) }
        #[cfg(windows)]
        { 
            use std::os::windows::process::ExitStatusExt;
            Ok(std::process::ExitStatus::from_raw(exit_code)) 
        }
    }
}

impl Drop for AppContainerChild {
    fn drop(&mut self) {
        unsafe {
            if !self.thread_handle.is_invalid() {
                let _ = CloseHandle(self.thread_handle);
            }
            if !self.process_handle.is_invalid() {
                let _ = CloseHandle(self.process_handle);
            }
        }
    }
}


pub fn spawn_custom(
    cmd: &str, 
    args: &[String], 
    policy: &SandboxPolicy // CHANGED
) -> Result<(AppContainerChild, Option<Box<dyn AsyncWrite + Unpin + Send>>, Option<Box<dyn AsyncRead + Unpin + Send>>, Option<Box<dyn AsyncRead + Unpin + Send>>)> {
    
    // 1. Create Pipes
    let mut h_stdin_read = HANDLE::default();
    let mut h_stdin_write = HANDLE::default();
    let mut h_stdout_read = HANDLE::default();
    let mut h_stdout_write = HANDLE::default();
    let mut h_stderr_read = HANDLE::default();
    let mut h_stderr_write = HANDLE::default();
    
    // 2. Prepare Attributes (AppContainer)
    let profile_name = format!("Sentinel-{}", uuid::Uuid::new_v4());
    
    let profile_name_wide: Vec<u16> = profile_name.encode_utf16().chain(std::iter::once(0)).collect();
    let profile_name_pcwstr = windows::core::PCWSTR(profile_name_wide.as_ptr());

    // Resolve cmd path
    let cmd_full_path = if std::path::Path::new(cmd).is_absolute() {
        cmd.to_string()
    } else {
        if let Ok(p) = std::process::Command::new("where").arg(cmd).output() {
            String::from_utf8_lossy(&p.stdout).lines().next().unwrap_or(cmd).trim().to_string()
        } else {
            cmd.to_string()
        }
    };

    tracing::info!("Creating AppContainer Profile: {}", profile_name);
    let sid = match unsafe { CreateAppContainerProfile(
        profile_name_pcwstr,
        profile_name_pcwstr,
        profile_name_pcwstr,
        None
    ) } {
        Ok(s) => s,
        Err(_e) => {
             unsafe {
                 DeriveAppContainerSidFromAppContainerName(profile_name_pcwstr)?
             }
        }
    };
    
        // 2b. Grant Permissions
        unsafe {
            let _ = grant_path_access(&cmd_full_path, sid);
            // Grant access to explicitly whitelisted paths from policy
            for p in &policy.read_paths {
                 let path_str = p.to_string_lossy();
                 tracing::info!("Granting sandbox access to: {}", path_str);
                 let _ = grant_path_access(&path_str, sid);
            }
            // For now, write paths separate? grant_path_access gives GenericRead|Execute.
            // We need a separate grant_write logic if we want to differentiate.
            // But minimal first.
            
            // Critical for LPAC: SystemRoot
            // We ALWAYS enable LPAC now ("Secure by Default").
            let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
            tracing::debug!("Granting SystemRoot access for LPAC: {}", system_root);
            let _ = grant_path_access(&system_root, sid);
        }

    
    let mut capabilities = windows::Win32::Security::SECURITY_CAPABILITIES {
        AppContainerSid: sid,
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    
    // TODO: Map policy.allow_network to explicit Capability SIDs (internetClient) if needed.
    
    let mut size: usize = 0;
    // Always 2 attrs: Security Caps + LPAC Policy
    let attribute_count = 2; 

    unsafe {
        let _ = InitializeProcThreadAttributeList(None, attribute_count, Some(0), &mut size);
    }
    let mut attr_list_buffer = vec![0u8; size];
    let lp_attr_list = windows::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buffer.as_mut_ptr() as *mut _);
    
    unsafe {
        InitializeProcThreadAttributeList(Some(lp_attr_list), attribute_count, Some(0), &mut size)?;
        
        // 1. Security Capabilities
        UpdateProcThreadAttribute(
            lp_attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize, 
            Some(&mut capabilities as *mut _ as *const std::ffi::c_void),
            std::mem::size_of::<windows::Win32::Security::SECURITY_CAPABILITIES>(),
            None,
            None
        )?;

        // 2. LPAC Policy (Review: Is this truly "Secure by Default"? Yes.)
        let mut policy_val: u32 = 1; 
        UpdateProcThreadAttribute(
            lp_attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
            Some(&mut policy_val as *mut _ as *const std::ffi::c_void),
            std::mem::size_of::<u32>(),
            None,
            None
        )?;
    }
    
    // Pipes setup (Standard)
    let mut sa = windows::Win32::Security::SECURITY_ATTRIBUTES::default();
    sa.nLength = std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32;
    sa.bInheritHandle = BOOL::from(true);
    let mut sd = windows::Win32::Security::SECURITY_DESCRIPTOR::default();
    unsafe {
        windows::Win32::Security::InitializeSecurityDescriptor(
            windows::Win32::Security::PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut _),
            1
        )?;
        windows::Win32::Security::SetSecurityDescriptorDacl(
            windows::Win32::Security::PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut _),
            true, None, false
        )?;
        sa.lpSecurityDescriptor = &mut sd as *mut _ as *mut _;
    }

    unsafe {
        CreatePipe(&mut h_stdin_read, &mut h_stdin_write, Some(&sa), 0)?;
        CreatePipe(&mut h_stdout_read, &mut h_stdout_write, Some(&sa), 0)?;
        CreatePipe(&mut h_stderr_read, &mut h_stderr_write, Some(&sa), 0)?;
        
        let _ = windows::Win32::Foundation::SetHandleInformation(h_stdin_write, 1, windows::Win32::Foundation::HANDLE_FLAGS(0));
        let _ = windows::Win32::Foundation::SetHandleInformation(h_stdout_read, 1, windows::Win32::Foundation::HANDLE_FLAGS(0));
        let _ = windows::Win32::Foundation::SetHandleInformation(h_stderr_read, 1, windows::Win32::Foundation::HANDLE_FLAGS(0));
    }

    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = h_stdin_read;
    si.StartupInfo.hStdOutput = h_stdout_write;
    si.StartupInfo.hStdError = h_stderr_write;
    si.lpAttributeList = lp_attr_list;

    let mut pi = PROCESS_INFORMATION::default();
    
    // Construct command line
    let mut cmd_line_str = format!("\"{}\"", cmd_full_path);
    for arg in args {
        // Basic escaping
        if arg.contains(' ') || arg.contains('"') {
             cmd_line_str.push_str(&format!(" \"{}\"", arg.replace("\"", "\\\"")));
        } else {
             cmd_line_str.push_str(&format!(" {}", arg));
        }
    }
    let mut cmd_line = cmd_line_str.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    
    unsafe {
        CreateProcessW(
            None,
            Some(windows::core::PWSTR(cmd_line.as_mut_ptr())),
            None,
            None,
            true, 
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            None,
            &si.StartupInfo,
            &mut pi
        )?;
        
        let _ = CloseHandle(h_stdin_read);
        let _ = CloseHandle(h_stdout_write);
        let _ = CloseHandle(h_stderr_write);
        
        DeleteProcThreadAttributeList(lp_attr_list);
    }

    let stdin_file = unsafe { tokio::fs::File::from_raw_handle(h_stdin_write.0 as RawHandle) };
    let stdout_file = unsafe { tokio::fs::File::from_raw_handle(h_stdout_read.0 as RawHandle) };
    let stderr_file = unsafe { tokio::fs::File::from_raw_handle(h_stderr_read.0 as RawHandle) };

    Ok((
        AppContainerChild {
            process_handle: pi.hProcess,
            thread_handle: pi.hThread,
        },
        Some(Box::new(stdin_file)),
        Some(Box::new(stdout_file)),
        Some(Box::new(stderr_file))
    ))
}


unsafe fn grant_path_access(path: &str, sid: PSID) -> Result<()> {
    let path_wide: Vec<u16> = OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();
    
    let mut explicit = EXPLICIT_ACCESS_W::default();
    // GENERIC_READ | GENERIC_EXECUTE = 0x80000000 | 0x20000000 = 0xA0000000? NO.
    // 0x1200a9 is a numeric constant for READ_CONTROL | SYNCHRONIZE | FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
    explicit.grfAccessPermissions = 0x1200a9; 
    explicit.grfAccessMode = GRANT_ACCESS;
    explicit.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    
    explicit.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    explicit.Trustee.ptstrName = windows::core::PWSTR(sid.0 as *mut _);
    
    let mut new_acl: *mut ACL = std::ptr::null_mut();
    
    let res = SetEntriesInAclW(Some(&[explicit]), None, &mut new_acl);
    if res != windows::Win32::Foundation::WIN32_ERROR(0) {
        return Err(anyhow::anyhow!("Failed to create ACL: {:?}", res));
    }
    
    let res = SetNamedSecurityInfoW(
        windows::core::PCWSTR(path_wide.as_ptr()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        None,
        None,
        Some(new_acl),
        None
    );
    
    if res != windows::Win32::Foundation::WIN32_ERROR(0) {
         // This often happens for global system files which we can't modify.
         // Debug log is appropriate.
         tracing::debug!("Failed to set security info for {}: {:?}", path, res);
    }
    
    Ok(())
}

