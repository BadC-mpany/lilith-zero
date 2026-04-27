// Copyright 2026 BadCompany
// Red-team security verification for process isolation and orphans

use tokio::process::Command;
use std::process::Stdio;
use std::time::Duration;
use tokio::time::sleep;
use std::fs;

#[tokio::test]
async fn test_exploit_daemonization_escape() {
    // This test verifies that if an MCP tool double-forks to daemonize,
    // Lilith-Zero's process group kill correctly cleans it up.
    
    let test_dir = tempfile::tempdir().unwrap();
    let marker_file = test_dir.path().join("daemon_running.marker");
    
    // A simple script that double-forks and writes to a marker file
    // We use a simpler python script that doesn't rely on bash -c complexity if possible
    let script = format!(
        "import os, sys, time; \
        pid = os.fork(); \
        if pid > 0: sys.exit(0); \
        os.setsid(); \
        pid = os.fork(); \
        if pid > 0: sys.exit(0); \
        while True: \
            with open('{}', 'w') as f: f.write('running'); \
            time.sleep(0.05)",
        marker_file.display()
    );

    // Path to lilith-zero binary
    let lilith_bin = std::env::var("LILITH_ZERO_BINARY_PATH")
        .unwrap_or_else(|_| "./target/debug/lilith-zero".to_string());

    // Run lilith-zero wrapping the daemonizing script
    let mut child = Command::new(lilith_bin)
        .arg("run")
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn lilith-zero");

    // Wait for the daemon to start and write the marker
    let mut found = false;
    for _ in 0..50 {
        if marker_file.exists() {
            found = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(found, "Daemon failed to start and write marker file");

    // Kill the lilith-zero supervisor
    child.kill().await.expect("Failed to kill lilith-zero");
    let _ = child.wait().await;

    // Wait to see if the daemon is still running
    // If PGID kill works, the daemon should be dead.
    sleep(Duration::from_millis(500)).await;
    
    // Remove the marker and wait again to see if it's recreated
    if marker_file.exists() {
        let _ = fs::remove_file(&marker_file);
    }
    
    sleep(Duration::from_millis(500)).await;
    assert!(!marker_file.exists(), "DAEMON ESCAPED! Marker file was recreated after supervisor kill.");
}
