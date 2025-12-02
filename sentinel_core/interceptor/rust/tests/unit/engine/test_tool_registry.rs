// Unit tests for tool registry loader

use sentinel_interceptor::loader::tool_registry::ToolRegistry;

#[test]
fn test_tool_registry_loading() {
    // Test with actual tool_registry.yaml
    let registry = ToolRegistry::from_file("../../../../../rule_maker/data/tool_registry.yaml");
    
    if let Ok(reg) = registry {
        // Test specific tools from the registry
        let web_search_classes = reg.get_tool_classes("web_search");
        assert!(web_search_classes.contains(&"CONSEQUENTIAL_WRITE".to_string()));

        let read_file_classes = reg.get_tool_classes("read_file");
        assert!(read_file_classes.contains(&"SENSITIVE_READ".to_string()));

        // Test non-existent tool returns empty vec
        let unknown_classes = reg.get_tool_classes("unknown_tool");
        assert_eq!(unknown_classes.len(), 0);
    }
}

