//! Policy evaluation engine: pattern matching and taint-rule evaluation.

/// Policy rule evaluation against tool calls and session state.
pub mod evaluator;
/// Logic condition and wildcard pattern matching.
pub mod pattern_matcher;
/// Cedar policy evaluation engine.
pub mod cedar_evaluator;
/// Compiler for YAML policies to Cedar.
pub mod yaml_to_cedar;
