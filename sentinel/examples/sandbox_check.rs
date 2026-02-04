#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        use sentinel::mcp::sandbox::SandboxPolicy;
        use sentinel::mcp::process::ProcessSupervisor;
        use sentinel::mcp::pipeline::UpstreamEvent;
        use tokio::sync::mpsc;
        
        let config = SandboxPolicy {
             read_paths: vec![],
             write_paths: vec![], 
             allow_network: false,
             ..Default::default()
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

        let (tx, _rx) = mpsc::channel::<UpstreamEvent>(32);

        let (mut supervisor, _, _, _) = match ProcessSupervisor::spawn("powershell", &args, Some(config), tx) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to spawn: {}", e);
                std::process::exit(1);
            }
        };
        
        // ProcessSupervisor doesn't expose underlying child wait directly anymore, we rely on its drop or we can add a method?
        // Wait, ProcessSupervisor runs a background task that waits.
        // But for this test we want to wait for the process to finish.
        // supervisor.kill() sends a kill signal.
        // We need to wait a bit or check file existence loops.
        // Actually, let's just wait a second as a simple check, or better yet, ProcessSupervisor doesn't have a join handle exposed.
        // But the background task sends an event.
        
        // Let's assume after 2 seconds it should be done.
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        
        // Check if file created
        if std::path::Path::new(target).exists() {
             eprintln!("FAILURE: File was written! Sandbox breach.");
             let _ = std::fs::remove_file(target);
             std::process::exit(1);
        } else {
             println!("SUCCESS: File was NOT written from sandboxed process.");
        }
        
        supervisor.kill();
    }
    
    #[cfg(not(windows))]
    println!("Skipping Windows Sandbox check on non-Windows");
    
    Ok(())
}
