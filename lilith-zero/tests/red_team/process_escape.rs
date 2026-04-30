// Copyright 2026 BadCompany
// Red-team security verification for process isolation and orphans

use tokio::process::Command;
use std::process::Stdio;
use std::time::Duration;
use tokio::time::sleep;
use std::fs;
use std::io::Write as _;

#[tokio::test]
async fn test_exploit_daemonization_escape() {
    // This test verifies that if an MCP tool double-forks to daemonize,
    // Lilith-Zero correctly cleans it up even if it was spawned via 'run' or 'hook'.
    
    let test_dir = tempfile::tempdir().unwrap();
    let marker_file = test_dir.path().join("daemon_running.marker");
    let script_file = test_dir.path().join("daemon.py");
    
    // A simple script that double-forks and writes to a marker file
    let script = format!(
        "import os, sys, time
pid = os.fork()
if pid > 0: sys.exit(0)
os.setsid()
pid = os.fork()
if pid > 0: sys.exit(0)
while True:
    try:
        with open('{}', 'w') as f:
            f.write('running')
            f.flush()
    except:
        pass
    time.sleep(0.01)",
        marker_file.display()
    );
    
    fs::File::create(&script_file).unwrap().write_all(script.as_bytes()).unwrap();

    // Path to lilith-zero binary
    let lilith_bin = std::env::var("LILITH_ZERO_BINARY_PATH")
        .unwrap_or_else(|_| "./target/debug/lilith-zero".to_string());

    // dummy policy
    let policy_file = test_dir.path().join("policy.yaml");
    fs::File::create(&policy_file).unwrap().write_all(b"
id: test-pgid
customer_id: test
name: Test PGID
version: 1
static_rules:
  python3: ALLOW
taint_rules: []
resource_rules: []
").unwrap();

    // Run lilith-zero
    let mut child = Command::new(&lilith_bin)
        .arg("run")
        .arg("--transport")
        .arg("stdio")
        .arg("-u")
        .arg("python")
        .arg("--policy")
        .arg(&policy_file)
        .arg("--")
        .arg(script_file.display().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn lilith-zero");

    let mut stdin = child.stdin.take().unwrap();
    
    // Send MCP initialize request to trigger child spawn
    let init_req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0.0"}}}"#;
    let payload = format!("Content-Length: {}\r\n\r\n{}", init_req.len(), init_req);
    tokio::io::AsyncWriteExt::write_all(&mut stdin, payload.as_bytes()).await.unwrap();
    tokio::io::AsyncWriteExt::flush(&mut stdin).await.unwrap();

    // Wait for the daemon to start and write the marker
    let mut found = false;
    for _ in 0..100 { 
        if marker_file.exists() {
            let content = fs::read_to_string(&marker_file).unwrap_or_default();
            if content == "running" {
                found = true;
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    
    if !found {
        let _ = child.kill().await;
        let mut stderr_buf = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            use tokio::io::AsyncReadExt;
            let _ = stderr.read_to_string(&mut stderr_buf).await;
        }
        eprintln!("Supervisor stderr: {}", stderr_buf);
        panic!("Daemon failed to start and write marker file within 10s");
    }

    // Kill the lilith-zero supervisor. This should kill the whole PGID.
    child.kill().await.expect("Failed to kill lilith-zero");
    let _ = child.wait().await;

    // Wait to see if the daemon is still running
    sleep(Duration::from_millis(500)).await;
    
    // Remove the marker
    if marker_file.exists() {
        let _ = fs::remove_file(&marker_file);
    }
    
    // If PGID kill failed, the daemon will recreate the file
    sleep(Duration::from_millis(1000)).await;
    assert!(!marker_file.exists(), "DAEMON ESCAPED! Marker file was recreated after supervisor kill.");
}
