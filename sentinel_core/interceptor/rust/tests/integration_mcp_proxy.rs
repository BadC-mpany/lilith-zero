// Integration tests for MCP proxy client
// Standalone test file to avoid compilation issues with other integration tests

#[path = "integration/test_mcp_proxy.rs"]
mod test_mcp_proxy;

#[path = "integration/test_proxy_timeout.rs"]
mod test_proxy_timeout;

#[path = "integration/test_proxy_load.rs"]
mod test_proxy_load;

