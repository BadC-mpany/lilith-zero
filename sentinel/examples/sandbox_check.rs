#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        use sentinel::mcp::sandbox::SandboxConfig;
        use sentinel::mcp::process::ProcessSupervisor;
        
        let config = SandboxConfig {
             strict_mode: true,
             allowed_read_paths: vec![],
             allowed_write_paths: vec![], 
             allow_network: false,
        };
        
        // Try to write to a temp file
        let target = "C:\\Users\\Public\\sentinel_sandbox_fail.txt";
        // Clean up previous run
        if std::path::Path::new(target).exists() {
            let _ = std::fs::remove_file(target);
        }

        let script = format!("echo sensitive > {}", target);
        
        println!("Spawning sandboxed process (powershell)...");
        let args = vec!["-c".to_string(), script];
        let (mut supervisor, _, _, _) = match ProcessSupervisor::spawn("powershell", &args, Some(config)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to spawn: {}", e);
                std::process::exit(1);
            }
        };
        
        let status = supervisor.child.wait().await?;
        println!("Process exited with: {:?}", status);
        
        // Check if file created
        if std::path::Path::new(target).exists() {
             eprintln!("FAILURE: File was written! Sandbox breach.");
             let _ = std::fs::remove_file(target);
             std::process::exit(1);
        } else {
             println!("SUCCESS: File was NOT written from sandboxed process.");
        }
    }
    
    #[cfg(not(windows))]
    println!("Skipping Windows Sandbox check on non-Windows");
    
    Ok(())
}
