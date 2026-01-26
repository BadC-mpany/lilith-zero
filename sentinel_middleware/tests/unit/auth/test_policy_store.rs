// Unit tests for policy store

use sentinel_interceptor::auth::policy_store::YamlPolicyStore;
use sentinel_interceptor::loader::policy_loader::PolicyLoader;
use sentinel_interceptor::api::PolicyStore;
use std::io::Write;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_yaml_policy_store_load() {
    let yaml_content = r#"
customers:
  - api_key: "test_key"
    owner: "test"
    mcp_upstream_url: "http://localhost:9000"
    policy_name: "test_policy"
policies:
  - name: "test_policy"
    static_rules:
      read_file: "ALLOW"
      delete_file: "DENY"
    taint_rules: []
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", yaml_content).unwrap();
    let path = temp_file.path();

    let loader = PolicyLoader::from_file(path).unwrap();
    let store = YamlPolicyStore::new(loader);

    let policy = store.load_policy("test_policy").await.unwrap();
    assert!(policy.is_some(), "Should load existing policy");
    
    let policy = policy.unwrap();
    assert_eq!(policy.name, "test_policy");
    assert!(policy.static_rules.contains_key("read_file"));
    assert_eq!(policy.static_rules.get("read_file"), Some(&"ALLOW".to_string()));
    assert_eq!(policy.static_rules.get("delete_file"), Some(&"DENY".to_string()));
}

#[tokio::test]
async fn test_yaml_policy_store_not_found() {
    let yaml_content = r#"
customers:
  - api_key: "test_key"
    owner: "test"
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
    let store = YamlPolicyStore::new(loader);

    let policy = store.load_policy("nonexistent_policy").await.unwrap();
    assert!(policy.is_none(), "Should return None for nonexistent policy");
}

#[tokio::test]
async fn test_yaml_policy_store_with_taint_rules() {
    let yaml_content = r#"
customers:
  - api_key: "test_key"
    owner: "test"
    mcp_upstream_url: "http://localhost:9000"
    policy_name: "test_policy"
policies:
  - name: "test_policy"
    static_rules:
      read_file: "ALLOW"
    taint_rules:
      - tool: "read_file"
        action: "ADD_TAINT"
        tag: "sensitive_data"
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", yaml_content).unwrap();
    let path = temp_file.path();

    let loader = PolicyLoader::from_file(path).unwrap();
    let store = YamlPolicyStore::new(loader);

    let policy = store.load_policy("test_policy").await.unwrap().unwrap();
    assert_eq!(policy.taint_rules.len(), 1);
    assert_eq!(policy.taint_rules[0].tool, Some("read_file".to_string()));
    assert_eq!(policy.taint_rules[0].action, "ADD_TAINT");
}

