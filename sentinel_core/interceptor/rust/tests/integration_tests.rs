// Integration test harness - includes all integration tests from tests/integration/

#[path = "integration/test_mcp_proxy.rs"]
mod test_mcp_proxy;

#[path = "integration/test_auth_middleware.rs"]
mod test_auth_middleware;

#[path = "integration/test_full_request_flow.rs"]
mod test_full_request_flow;

#[path = "integration/test_pattern_matching.rs"]
mod test_pattern_matching;

#[path = "integration/test_policy_evaluation.rs"]
mod test_policy_evaluation;

#[path = "integration/test_taint_tracking.rs"]
mod test_taint_tracking;

