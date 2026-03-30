//! Policy evaluation engine: pattern matching and taint-rule evaluation.

/// Policy rule evaluation against tool calls and session state.
pub mod evaluator;
/// Logic condition and wildcard pattern matching.
pub mod pattern_matcher;
