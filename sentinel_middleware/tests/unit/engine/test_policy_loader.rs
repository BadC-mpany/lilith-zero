// Unit tests for policy loader

use sentinel_interceptor::loader::policy_loader::PolicyLoader;

#[test]
fn test_policy_loader() {
    // Test with actual policies.yaml
    let loader = PolicyLoader::from_file("../../../policies.yaml");
    
    if let Ok(loader) = loader {
        // Test customer lookup
        let customer = loader.get_customer_config("sk_live_demo_123");
        assert!(customer.is_some());
        
        if let Some(customer) = customer {
            assert_eq!(customer.owner, "Demo User");
            assert_eq!(customer.policy_name, "default_policy");
        }

        // Test policy lookup
        let policy = loader.get_policy("default_policy");
        assert!(policy.is_some());

        // Test validation
        assert!(loader.validate().is_ok());
    }
}

