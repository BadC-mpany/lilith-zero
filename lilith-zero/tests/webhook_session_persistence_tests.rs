//! Integration tests for webhook session persistence.
//!
//! Tests cover:
//! - Basic disk I/O (save, load, new session)
//! - Agent isolation (different agents use different policies)
//! - Conversation isolation (different conversations have separate taints)
//! - Concurrency safety (parallel requests don't corrupt state)
//! - Edge cases (malformed files, permissions errors, path sanitization)
//! - Taint tracking integration (lethal trifecta, rate limiting, replay detection)

#![cfg(feature = "webhook")]

use lilith_zero::engine_core::persistence::PersistenceLayer;
use lilith_zero::engine_core::security_core::SessionState;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

/// Create a temporary session storage directory for a test.
fn temp_storage_dir() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("failed to create temp dir");
    let path = dir.path().to_path_buf();
    (dir, path)
}

/// Create a simple test SessionState with no taints.
fn empty_session_state() -> SessionState {
    SessionState {
        taints: HashSet::new(),
        history: Vec::new(),
        call_count: 0,
        call_timestamps_ms: Vec::new(),
        seen_request_ids: HashMap::new(),
    }
}

/// Create a SessionState with a specific taint.
fn session_with_taint(taint: &str) -> SessionState {
    let mut state = empty_session_state();
    state.taints.insert(taint.to_string());
    state
}

// ============================================================================
// Phase 3a: Basic Persistence Tests
// ============================================================================

#[test]
fn test_webhook_single_request_saves_session_to_disk() {
    let (_dir, storage_path) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_path.clone());

    let conversation_id = "conv-001";
    let mut lock = persistence.lock(conversation_id).expect("lock failed");

    let state = session_with_taint("UNTRUSTED_SOURCE");
    lock.save(&state).expect("save failed");
    drop(lock);

    // Verify file was created.
    let expected_file = storage_path.join("conv-001.json");
    assert!(
        expected_file.exists(),
        "Session file not created at {}",
        expected_file.display()
    );

    // Verify file contains the taint.
    let contents = fs::read_to_string(&expected_file).expect("read file failed");
    assert!(
        contents.contains("UNTRUSTED_SOURCE"),
        "Taint not found in session file"
    );
}

#[test]
fn test_webhook_session_loads_from_disk() {
    let (_dir, storage_path) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_path.clone());

    let conversation_id = "conv-002";

    // First request: save a state with a taint.
    {
        let mut lock = persistence.lock(conversation_id).expect("lock 1 failed");
        let state = session_with_taint("UNTRUSTED_SOURCE");
        lock.save(&state).expect("save failed");
    }

    // Second request: load from disk and verify taint is present.
    {
        let mut lock = persistence.lock(conversation_id).expect("lock 2 failed");
        let loaded = lock.load().expect("load failed");
        assert!(loaded.is_some(), "Session should not be empty");

        let loaded_state = loaded.unwrap();
        assert!(
            loaded_state.taints.contains("UNTRUSTED_SOURCE"),
            "Taint not persisted across requests"
        );
    }
}

#[test]
fn test_webhook_new_session_starts_empty() {
    let (_dir, storage_path) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_path.clone());

    let conversation_id = "conv-003";

    // Lock creates the file, but load() returns None for an empty file.
    let mut lock = persistence.lock(conversation_id).expect("lock failed");
    let loaded = lock.load().expect("load failed");

    assert!(
        loaded.is_none(),
        "New session should be empty (no state written yet)"
    );

    // Verify file exists (lock creates it) but is empty.
    let expected_file = storage_path.join("conv-003.json");
    assert!(expected_file.exists(), "File should exist after lock()");

    let contents = std::fs::read_to_string(&expected_file).expect("read file failed");
    assert!(contents.trim().is_empty(), "File should be empty initially");
}

// ============================================================================
// Phase 3b: Multi-Agent Isolation Tests
// ============================================================================

#[test]
fn test_webhook_different_agents_isolated_sessions() {
    let (_dir, storage_path) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_path.clone());

    let conversation_id = "shared-conv";
    let agent_a = "agent-A";
    let agent_b = "agent-B";

    // Agent A adds a taint.
    {
        let mut lock = persistence
            .lock(&format!("{}-{}", conversation_id, agent_a))
            .expect("lock A failed");
        let state = session_with_taint("TAINT_A");
        lock.save(&state).expect("save A failed");
    }

    // Agent B checks the same conversation_id (but different session key).
    // It should have no taint from Agent A.
    {
        let mut lock = persistence
            .lock(&format!("{}-{}", conversation_id, agent_b))
            .expect("lock B failed");
        let loaded = lock.load().expect("load B failed");
        assert!(loaded.is_none(), "Agent B should not see Agent A's taints");
    }
}

// ============================================================================
// Phase 3c: Conversation Isolation Tests
// ============================================================================

#[test]
fn test_webhook_different_conversations_have_separate_taints() {
    let (_dir, storage_path) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_path.clone());

    // Conversation 1: add TAINT_A
    {
        let mut lock = persistence.lock("conversation-1").expect("lock 1 failed");
        let state = session_with_taint("TAINT_A");
        lock.save(&state).expect("save 1 failed");
    }

    // Conversation 2: should not have TAINT_A
    {
        let mut lock = persistence.lock("conversation-2").expect("lock 2 failed");
        let loaded = lock.load().expect("load 2 failed");
        assert!(
            loaded.is_none(),
            "Conversation 2 should not inherit Conversation 1's taints"
        );
    }
}

#[test]
fn test_webhook_two_conversations_same_agent_isolated() {
    let (_dir, storage_path) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_path.clone());

    let agent_id = "agent-001";

    // Conversation 1: taint with TAINT_A
    {
        let session_key = format!("conv-1-{}", agent_id);
        let mut lock = persistence.lock(&session_key).expect("lock 1 failed");
        let state = session_with_taint("TAINT_A");
        lock.save(&state).expect("save 1 failed");
    }

    // Conversation 2: taint with TAINT_B
    {
        let session_key = format!("conv-2-{}", agent_id);
        let mut lock = persistence.lock(&session_key).expect("lock 2 failed");
        let state = session_with_taint("TAINT_B");
        lock.save(&state).expect("save 2 failed");
    }

    // Verify Conversation 1 still has TAINT_A only.
    {
        let session_key = format!("conv-1-{}", agent_id);
        let mut lock = persistence
            .lock(&session_key)
            .expect("lock verify 1 failed");
        let loaded = lock.load().expect("load verify 1 failed");
        let state = loaded.unwrap();
        assert!(
            state.taints.contains("TAINT_A"),
            "Conv 1 should have TAINT_A"
        );
        assert!(
            !state.taints.contains("TAINT_B"),
            "Conv 1 should not have TAINT_B"
        );
    }

    // Verify Conversation 2 still has TAINT_B only.
    {
        let session_key = format!("conv-2-{}", agent_id);
        let mut lock = persistence
            .lock(&session_key)
            .expect("lock verify 2 failed");
        let loaded = lock.load().expect("load verify 2 failed");
        let state = loaded.unwrap();
        assert!(
            !state.taints.contains("TAINT_A"),
            "Conv 2 should not have TAINT_A"
        );
        assert!(
            state.taints.contains("TAINT_B"),
            "Conv 2 should have TAINT_B"
        );
    }
}

// ============================================================================
// Phase 3d: Concurrency & Safety Tests
// ============================================================================

#[test]
fn test_webhook_concurrent_requests_same_conversation() {
    let (_dir, storage_path) = temp_storage_dir();
    let storage_arc = Arc::new(storage_path);

    let conversation_id = "concurrent-conv";
    let num_threads = 5;
    let mut handles = vec![];

    // Spawn 5 threads, each incrementing call_count in the same conversation.
    for _ in 0..num_threads {
        let storage = storage_arc.clone();
        let conv_id = conversation_id.to_string();

        let handle = std::thread::spawn(move || {
            let persistence = PersistenceLayer::new((*storage).clone());

            // Load, increment, save.
            let mut lock = persistence.lock(&conv_id).expect("lock failed");
            let mut state = match lock.load().expect("load failed") {
                Some(s) => s,
                None => empty_session_state(),
            };

            state.call_count += 1;

            lock.save(&state).expect("save failed");
        });

        handles.push(handle);
    }

    // Wait for all threads.
    for handle in handles {
        handle.join().expect("thread panic");
    }

    // Verify final state has all 5 increments.
    {
        let persistence = PersistenceLayer::new((*storage_arc).clone());
        let mut lock = persistence
            .lock(conversation_id)
            .expect("final lock failed");
        let loaded = lock.load().expect("final load failed");
        let state = loaded.expect("final state should exist");

        assert_eq!(
            state.call_count, num_threads as u32,
            "call_count should be {} after concurrent requests",
            num_threads
        );
    }
}

#[test]
fn test_webhook_concurrent_requests_different_conversations() {
    let (_dir, storage_path) = temp_storage_dir();
    let storage_arc = Arc::new(storage_path);

    let num_threads = 5;
    let mut handles = vec![];

    // Spawn 5 threads, each modifying a different conversation.
    for i in 0..num_threads {
        let storage = storage_arc.clone();

        let handle = std::thread::spawn(move || {
            let persistence = PersistenceLayer::new((*storage).clone());
            let conversation_id = format!("conv-{}", i);

            let mut lock = persistence.lock(&conversation_id).expect("lock failed");
            let mut state = empty_session_state();
            state.taints.insert(format!("TAINT_{}", i));

            lock.save(&state).expect("save failed");
        });

        handles.push(handle);
    }

    // Wait for all threads.
    for handle in handles {
        handle.join().expect("thread panic");
    }

    // Verify each conversation has its own taint.
    {
        let persistence = PersistenceLayer::new((*storage_arc).clone());
        for i in 0..num_threads {
            let conversation_id = format!("conv-{}", i);
            let mut lock = persistence
                .lock(&conversation_id)
                .expect("verify lock failed");
            let loaded = lock.load().expect("verify load failed");
            let state = loaded.expect("state should exist");

            let expected_taint = format!("TAINT_{}", i);
            assert!(
                state.taints.contains(&expected_taint),
                "Conv {} should have {}",
                i,
                expected_taint
            );
        }
    }
}

// ============================================================================
// Phase 3e: Edge Cases
// ============================================================================

#[test]
fn test_webhook_malformed_session_file_recovered() {
    let (_dir, storage_path) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_path.clone());

    let conversation_id = "malformed-conv";

    // Create a corrupted JSON file.
    let file_path = storage_path.join("malformed-conv.json");
    fs::write(&file_path, "{invalid json}").expect("write corrupt file failed");

    // Attempt to load should handle gracefully (return error, not panic).
    let mut lock = persistence.lock(conversation_id).expect("lock failed");
    let result = lock.load();

    // The load should fail gracefully with a parse error (not panic).
    assert!(result.is_err(), "Load should fail on malformed JSON");

    // Recovery: we can still save a new state (overwrites the corrupted file).
    let fresh_state = empty_session_state();
    lock.save(&fresh_state).expect("recovery save failed");

    // Verify recovery succeeded.
    drop(lock);
    let mut lock2 = persistence.lock(conversation_id).expect("lock 2 failed");
    let loaded = lock2.load().expect("load after recovery failed");
    assert!(
        loaded.is_some(),
        "Should have successfully recovered with fresh state"
    );
}

#[test]
fn test_webhook_session_id_sanitization() {
    let (_dir, storage_path) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_path.clone());

    // Use a conversation_id with invalid characters (path traversal attempts).
    let malicious_id = "../../../etc/passwd";
    let mut lock = persistence.lock(malicious_id).expect("lock failed");

    let state = session_with_taint("TEST");
    lock.save(&state).expect("save failed");

    // Verify the file was created safely (not at a path traversal location).
    // The file should be in storage_path/[sanitized_id].json
    let files: Vec<_> = fs::read_dir(&storage_path)
        .expect("read dir failed")
        .filter_map(|e| e.ok())
        .collect();

    assert_eq!(
        files.len(),
        1,
        "Should have exactly one file in storage dir (sanitization worked)"
    );

    // Verify the filename is safe.
    let file_name = files[0].file_name();
    let file_name_str = file_name.to_string_lossy();
    assert!(
        !file_name_str.contains('/') && !file_name_str.contains('\\'),
        "Filename should not contain path separators: {}",
        file_name_str
    );
}

#[test]
fn test_webhook_new_session_storage_dir_created() {
    let temp_dir = TempDir::new().expect("temp dir creation failed");
    let nested_path = temp_dir.path().join("nested").join("storage");

    assert!(
        !nested_path.exists(),
        "Nested path should not exist initially"
    );

    let persistence = PersistenceLayer::new(nested_path.clone());

    // Calling lock should create the directory if it doesn't exist.
    let _lock = persistence
        .lock("conv-001")
        .expect("lock should auto-create dir");

    assert!(
        nested_path.exists(),
        "Storage directory should have been created"
    );
}

// ============================================================================
// Phase 3f: Taint Tracking Integration
// ============================================================================

#[test]
fn test_webhook_multiple_taints_persisted() {
    let (_dir, storage_path) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_path.clone());

    let conversation_id = "multi-taint-conv";

    // Request 1: Add first taint.
    {
        let mut lock = persistence.lock(conversation_id).expect("lock 1 failed");
        let mut state = empty_session_state();
        state.taints.insert("UNTRUSTED_SOURCE".to_string());
        lock.save(&state).expect("save 1 failed");
    }

    // Request 2: Load and add second taint.
    {
        let mut lock = persistence.lock(conversation_id).expect("lock 2 failed");
        let mut state = lock.load().expect("load failed").unwrap();
        state.taints.insert("ACCESS_PRIVATE".to_string());
        lock.save(&state).expect("save 2 failed");
    }

    // Request 3: Verify both taints present (lethal trifecta check).
    {
        let mut lock = persistence.lock(conversation_id).expect("lock 3 failed");
        let state = lock.load().expect("load 3 failed").unwrap();
        assert!(state.taints.contains("UNTRUSTED_SOURCE"));
        assert!(state.taints.contains("ACCESS_PRIVATE"));
    }
}

#[test]
fn test_webhook_call_count_persisted() {
    let (_dir, storage_path) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_path.clone());

    let conversation_id = "rate-limit-conv";

    // Request 1: First call.
    {
        let mut lock = persistence.lock(conversation_id).expect("lock 1 failed");
        let mut state = empty_session_state();
        state.call_count = 1;
        lock.save(&state).expect("save 1 failed");
    }

    // Request 2: Increment call count.
    {
        let mut lock = persistence.lock(conversation_id).expect("lock 2 failed");
        let mut state = lock.load().expect("load failed").unwrap();
        state.call_count += 1;
        lock.save(&state).expect("save 2 failed");
    }

    // Request 3: Verify call_count = 2.
    {
        let mut lock = persistence.lock(conversation_id).expect("lock 3 failed");
        let state = lock.load().expect("load 3 failed").unwrap();
        assert_eq!(
            state.call_count, 2,
            "call_count should be persisted across requests"
        );
    }
}

#[test]
fn test_webhook_replay_detection_state_persisted() {
    let (_dir, storage_path) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_path.clone());

    let conversation_id = "replay-detection-conv";
    let request_id = "req-12345";

    // Request 1: Record first request.
    {
        let mut lock = persistence.lock(conversation_id).expect("lock 1 failed");
        let mut state = empty_session_state();
        state
            .seen_request_ids
            .insert(request_id.to_string(), 1000u64);
        lock.save(&state).expect("save 1 failed");
    }

    // Request 2: Load and verify request_id is remembered.
    {
        let mut lock = persistence.lock(conversation_id).expect("lock 2 failed");
        let state = lock.load().expect("load failed").unwrap();
        assert!(
            state.seen_request_ids.contains_key(request_id),
            "Request ID should be in replay detection map"
        );
    }
}

// ============================================================================
// TTL & Cleanup Tests
// ============================================================================

/// Test that cleanup_expired_sessions removes files older than TTL.
#[test]
fn test_cleanup_removes_expired_sessions() {
    let (_temp_dir, storage_dir) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_dir.clone());

    // Create a session file and save state.
    let session_key = "expired-session";
    {
        let mut lock = persistence.lock(session_key).expect("lock failed");
        let mut state = empty_session_state();
        state.taints.insert("OLD_TAINT".to_string());
        lock.save(&state).expect("save failed");
    }

    let session_file = storage_dir.join(format!("{}.json", session_key));
    assert!(session_file.exists(), "Session file should be created");

    // Set modification time to 48 hours ago.
    let now = std::time::SystemTime::now();
    let old_time = now - std::time::Duration::from_secs(48 * 3600);
    filetime::set_file_mtime(&session_file, old_time.into())
        .expect("failed to set old mtime");

    // Run cleanup with 24-hour TTL.
    let deleted = lilith_zero::server::webhook::cleanup_expired_sessions(&storage_dir, 24 * 3600)
        .expect("cleanup failed");

    assert_eq!(deleted, 1, "Should have deleted 1 expired file");
    assert!(
        !session_file.exists(),
        "Expired session file should be deleted"
    );
}

/// Test that cleanup_expired_sessions keeps files younger than TTL.
#[test]
fn test_cleanup_keeps_recent_sessions() {
    let (_temp_dir, storage_dir) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_dir.clone());

    // Create a session file and save state.
    let session_key = "recent-session";
    {
        let mut lock = persistence.lock(session_key).expect("lock failed");
        let mut state = empty_session_state();
        state.taints.insert("FRESH_TAINT".to_string());
        lock.save(&state).expect("save failed");
    }

    let session_file = storage_dir.join(format!("{}.json", session_key));
    assert!(session_file.exists(), "Session file should be created");

    // Set modification time to 1 hour ago (well within 24-hour TTL).
    let now = std::time::SystemTime::now();
    let recent_time = now - std::time::Duration::from_secs(3600);
    filetime::set_file_mtime(&session_file, recent_time.into())
        .expect("failed to set recent mtime");

    // Run cleanup with 24-hour TTL.
    let deleted = lilith_zero::server::webhook::cleanup_expired_sessions(&storage_dir, 24 * 3600)
        .expect("cleanup failed");

    assert_eq!(deleted, 0, "Should not delete recent files");
    assert!(session_file.exists(), "Recent session file should be kept");

    // Verify file contents are intact.
    let mut lock = persistence.lock(session_key).expect("lock failed");
    let loaded_state = lock.load().expect("load failed").unwrap();
    assert!(
        loaded_state.taints.contains("FRESH_TAINT"),
        "Taint should still be present"
    );
}

/// Test cleanup with mixed old and new files.
#[test]
fn test_cleanup_mixed_old_and_new_files() {
    let (_temp_dir, storage_dir) = temp_storage_dir();
    let persistence = PersistenceLayer::new(storage_dir.clone());

    // Create 3 session files: 2 old, 1 new.
    let old_sessions = vec!["old-session-1", "old-session-2"];
    let new_sessions = vec!["new-session"];

    for session_key in old_sessions.iter().chain(new_sessions.iter()) {
        let mut lock = persistence.lock(session_key).expect("lock failed");
        let state = empty_session_state();
        lock.save(&state).expect("save failed");
    }

    // Set old files to 48 hours ago.
    let now = std::time::SystemTime::now();
    let old_time = now - std::time::Duration::from_secs(48 * 3600);
    for session_key in &old_sessions {
        let file = storage_dir.join(format!("{}.json", session_key));
        filetime::set_file_mtime(&file, old_time.into())
            .expect("failed to set old mtime");
    }

    // Set new file to 1 hour ago.
    let recent_time = now - std::time::Duration::from_secs(3600);
    for session_key in &new_sessions {
        let file = storage_dir.join(format!("{}.json", session_key));
        filetime::set_file_mtime(&file, recent_time.into())
            .expect("failed to set recent mtime");
    }

    // Run cleanup with 24-hour TTL.
    let deleted = lilith_zero::server::webhook::cleanup_expired_sessions(&storage_dir, 24 * 3600)
        .expect("cleanup failed");

    assert_eq!(deleted, 2, "Should have deleted 2 old files");

    // Verify old files are gone.
    for session_key in &old_sessions {
        let file = storage_dir.join(format!("{}.json", session_key));
        assert!(!file.exists(), "Old file {} should be deleted", session_key);
    }

    // Verify new file still exists.
    for session_key in &new_sessions {
        let file = storage_dir.join(format!("{}.json", session_key));
        assert!(file.exists(), "New file {} should be kept", session_key);
    }
}

/// Test cleanup with empty directory.
#[test]
fn test_cleanup_empty_directory() {
    let (_temp_dir, storage_dir) = temp_storage_dir();

    // Run cleanup on empty directory.
    let deleted =
        lilith_zero::server::webhook::cleanup_expired_sessions(&storage_dir, 24 * 3600)
            .expect("cleanup failed");

    assert_eq!(deleted, 0, "Should delete 0 files from empty directory");
}

/// Test cleanup on non-existent directory.
#[test]
fn test_cleanup_nonexistent_directory() {
    let storage_dir = PathBuf::from("/tmp/lilith-nonexistent-cleanup-dir-12345");

    // Run cleanup on non-existent directory (should not panic).
    let deleted =
        lilith_zero::server::webhook::cleanup_expired_sessions(&storage_dir, 24 * 3600)
            .expect("cleanup failed");

    assert_eq!(deleted, 0, "Should return 0 for non-existent directory");
}
