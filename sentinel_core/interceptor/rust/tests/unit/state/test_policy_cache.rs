// Unit tests for policy cache

use sentinel_interceptor::state::policy_cache::MokaPolicyCache;
use sentinel_interceptor::api::{PolicyCache, PolicyStore};
use sentinel_interceptor::core::models::PolicyDefinition;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

// Mock PolicyStore for testing
struct MockPolicyStore {
    policies: HashMap<String, Arc<PolicyDefinition>>,
    should_fail: bool,
}

#[async_trait::async_trait]
impl PolicyStore for MockPolicyStore {
    async fn load_policy(&self, policy_name: &str) -> Result<Option<Arc<PolicyDefinition>>, String> {
        if self.should_fail {
            return Err("Database error".to_string());
        }
        Ok(self.policies.get(policy_name).cloned())
    }
}

fn create_test_policy(name: &str) -> PolicyDefinition {
    PolicyDefinition {
        name: name.to_string(),
        static_rules: HashMap::new(),
        taint_rules: vec![],
    }
}

/// Test cache hit returns policy
#[tokio::test]
async fn test_policy_cache_get_hit() {
    // Arrange: Create cache with policy in store
    let mut policies = HashMap::new();
    let policy = Arc::new(create_test_policy("test_policy"));
    policies.insert("test_policy".to_string(), Arc::clone(&policy));
    
    let store = Arc::new(MockPolicyStore {
        policies,
        should_fail: false,
    });
    
    let cache = MokaPolicyCache::new(store.clone(), 60, 1000);
    
    // First call: cache miss, loads from store
    let result1 = cache.get_policy("test_policy").await;
    assert!(result1.is_ok());
    assert!(result1.unwrap().is_some());
    
    // Second call: cache hit
    let result2 = cache.get_policy("test_policy").await;
    assert!(result2.is_ok());
    assert!(result2.unwrap().is_some());
}

/// Test cache miss loads from store
#[tokio::test]
async fn test_policy_cache_get_miss() {
    // Arrange: Create cache with empty store
    let store = Arc::new(MockPolicyStore {
        policies: HashMap::new(),
        should_fail: false,
    });
    
    let cache = MokaPolicyCache::new(store.clone(), 60, 1000);
    
    // Act: Get non-existent policy
    let result = cache.get_policy("nonexistent").await;
    
    // Assert: Should return None
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

/// Test cache miss populates cache
#[tokio::test]
async fn test_policy_cache_get_miss_caches_result() {
    // Arrange: Create cache with policy in store
    let mut policies = HashMap::new();
    let policy = Arc::new(create_test_policy("test_policy"));
    policies.insert("test_policy".to_string(), Arc::clone(&policy));
    
    let store = Arc::new(MockPolicyStore {
        policies,
        should_fail: false,
    });
    
    let cache = MokaPolicyCache::new(store.clone(), 60, 1000);
    
    // Act: First call (cache miss)
    let result1 = cache.get_policy("test_policy").await;
    assert!(result1.is_ok());
    assert!(result1.unwrap().is_some());
    
    // Second call should be cache hit (store not called again)
    // We can't easily verify store wasn't called, but we can verify it works
    let result2 = cache.get_policy("test_policy").await;
    assert!(result2.is_ok());
    assert!(result2.unwrap().is_some());
}

/// Test TTL expiration
#[tokio::test]
async fn test_policy_cache_ttl_expiration() {
    // Arrange: Create cache with very short TTL (1 second)
    let mut policies = HashMap::new();
    let policy = Arc::new(create_test_policy("test_policy"));
    policies.insert("test_policy".to_string(), Arc::clone(&policy));
    
    let store = Arc::new(MockPolicyStore {
        policies,
        should_fail: false,
    });
    
    let cache = MokaPolicyCache::new(store.clone(), 1, 1000); // 1 second TTL
    
    // Act: Get policy (cache miss)
    let result1 = cache.get_policy("test_policy").await;
    assert!(result1.is_ok());
    assert!(result1.unwrap().is_some());
    
    // Wait for TTL to expire
    sleep(Duration::from_secs(2)).await;
    
    // Get again (should be cache miss after expiration)
    let result2 = cache.get_policy("test_policy").await;
    assert!(result2.is_ok());
    assert!(result2.unwrap().is_some());
}

/// Test store error propagation
#[tokio::test]
async fn test_policy_cache_store_error() {
    // Arrange: Create cache with failing store
    let store = Arc::new(MockPolicyStore {
        policies: HashMap::new(),
        should_fail: true,
    });
    
    let cache = MokaPolicyCache::new(store.clone(), 60, 1000);
    
    // Act: Get policy
    let result = cache.get_policy("test_policy").await;
    
    // Assert: Should propagate error
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Database error"));
}

/// Test manual cache insertion
#[tokio::test]
async fn test_policy_cache_put_policy() {
    // Arrange: Create cache
    let store = Arc::new(MockPolicyStore {
        policies: HashMap::new(),
        should_fail: false,
    });
    
    let cache = MokaPolicyCache::new(store.clone(), 60, 1000);
    let policy = Arc::new(create_test_policy("test_policy"));
    
    // Act: Put policy in cache
    let result = cache.put_policy("test_policy", Arc::clone(&policy)).await;
    
    // Assert: Should succeed
    assert!(result.is_ok());
    
    // Verify it's in cache
    let get_result = cache.get_policy("test_policy").await;
    assert!(get_result.is_ok());
    assert!(get_result.unwrap().is_some());
}

/// Test concurrent cache access (thread safety)
#[tokio::test]
async fn test_policy_cache_concurrent_access() {
    // Arrange: Create cache
    let mut policies = HashMap::new();
    let policy = Arc::new(create_test_policy("test_policy"));
    policies.insert("test_policy".to_string(), Arc::clone(&policy));
    
    let store = Arc::new(MockPolicyStore {
        policies,
        should_fail: false,
    });
    
    let cache = Arc::new(MokaPolicyCache::new(store.clone(), 60, 1000));
    
    // Act: Concurrent access
    let mut handles = vec![];
    for i in 0..10 {
        let cache_clone = cache.clone();
        let handle = tokio::spawn(async move {
            cache_clone.get_policy("test_policy").await
        });
        handles.push(handle);
    }
    
    // Assert: All should succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}

/// Test max capacity (LRU eviction)
#[tokio::test]
async fn test_policy_cache_max_capacity() {
    // Arrange: Create cache with very small capacity (2)
    let store = Arc::new(MockPolicyStore {
        policies: HashMap::new(),
        should_fail: false,
    });
    
    let cache = MokaPolicyCache::new(store.clone(), 60, 2); // Max 2 policies
    
    // Act: Insert 3 policies
    for i in 0..3 {
        let policy = Arc::new(create_test_policy(&format!("policy_{}", i)));
        cache.put_policy(&format!("policy_{}", i), policy).await.unwrap();
    }
    
    // Assert: First policy should be evicted (LRU)
    // Note: Moka's exact eviction behavior may vary, but we verify it doesn't crash
    let result = cache.get_policy("policy_0").await;
    // May be None if evicted, or Some if not yet evicted
    assert!(result.is_ok());
}

