// Unit tests for customer store

use sentinel_interceptor::auth::customer_store::{YamlCustomerStore, FallbackCustomerStore};
use sentinel_interceptor::loader::policy_loader::PolicyLoader;
use std::io::Write;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_yaml_customer_store_lookup() {
    // Create a temporary YAML file
    let yaml_content = r#"
customers:
  - api_key: "test_key_123"
    owner: "test_owner"
    mcp_upstream_url: "http://localhost:9000"
    policy_name: "test_policy"
policies:
  - name: "test_policy"
    static_rules: {}
    taint_rules: []
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", yaml_content).unwrap();
    let path = temp_file.path();

    let loader = PolicyLoader::from_file(path).unwrap();
    let store = YamlCustomerStore::new(loader);

    let config = store.lookup_customer_by_key("test_key_123");
    assert!(config.is_some(), "Should find customer with valid key");
    
    let config = config.unwrap();
    assert_eq!(config.owner, "test_owner");
    assert_eq!(config.mcp_upstream_url, "http://localhost:9000");
    assert_eq!(config.policy_name, "test_policy");
}

#[tokio::test]
async fn test_yaml_customer_store_not_found() {
    let yaml_content = r#"
customers:
  - api_key: "test_key_123"
    owner: "test_owner"
    mcp_upstream_url: "http://localhost:9000"
    policy_name: "test_policy"
policies:
  - name: "test_policy"
    static_rules: {}
    taint_rules: []
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", yaml_content).unwrap();
    let path = temp_file.path();

    let loader = PolicyLoader::from_file(path).unwrap();
    let store = YamlCustomerStore::new(loader);

    let config = store.lookup_customer_by_key("invalid_key");
    assert!(config.is_none(), "Should return None for invalid key");
}

#[tokio::test]
async fn test_yaml_customer_store_multiple_customers() {
    let yaml_content = r#"
customers:
  - api_key: "key1"
    owner: "owner1"
    mcp_upstream_url: "http://localhost:9000"
    policy_name: "policy1"
  - api_key: "key2"
    owner: "owner2"
    mcp_upstream_url: "http://localhost:9001"
    policy_name: "policy2"
policies:
  - name: "policy1"
    static_rules: {}
    taint_rules: []
  - name: "policy2"
    static_rules: {}
    taint_rules: []
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", yaml_content).unwrap();
    let path = temp_file.path();

    let loader = PolicyLoader::from_file(path).unwrap();
    let store = YamlCustomerStore::new(loader);

    let config1 = store.lookup_customer_by_key("key1").unwrap();
    assert_eq!(config1.owner, "owner1");

    let config2 = store.lookup_customer_by_key("key2").unwrap();
    assert_eq!(config2.owner, "owner2");
}

