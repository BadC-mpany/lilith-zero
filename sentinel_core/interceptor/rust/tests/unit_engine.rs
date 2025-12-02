// Entry point for engine unit tests

#[path = "unit/engine"]
mod engine {
    mod test_evaluator;
    mod test_pattern_matcher;
    mod test_tool_registry;
    mod test_policy_loader;
    mod test_redis_store;
    mod test_exceptions;
    mod test_wildcard_matching;
}

