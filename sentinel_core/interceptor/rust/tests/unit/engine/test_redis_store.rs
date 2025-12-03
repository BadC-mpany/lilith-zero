// Unit tests for Redis store

use sentinel_interceptor::state::redis_store::RedisStore;

    #[tokio::test]
    async fn test_redis_operations() {
        // This test requires Redis to be running
        // Skip if Redis is not available
        let redis_url = "redis://localhost:6379";
        
        if let Ok(store) = RedisStore::new(redis_url).await {
            // Use unique session ID to avoid test pollution from previous runs
            let session_id = format!("test_session_{}", uuid::Uuid::new_v4());
        
            // Test taint operations (append-only)
            store.add_taint(&session_id, "sensitive_data").await.unwrap();
            let taints = store.get_taints(&session_id).await.unwrap();
            assert!(taints.contains("sensitive_data"));
            
            // Taints expire via TTL, not explicit deletion
            
            // Test history operations
            store.add_history_entry(&session_id, "read_file", &vec!["SENSITIVE_READ".to_string()], 1234567890.0).await.unwrap();
            let history = store.get_history(&session_id).await.unwrap();
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].tool, "read_file");
        }
    }

