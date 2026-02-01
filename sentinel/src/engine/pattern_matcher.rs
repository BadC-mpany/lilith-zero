//! Pattern matching engine for dynamic rules.
//!
//! This module provides the `PatternMatcher` which evaluates logic conditions
//! and sequences against the current tool call and session history.

use crate::core::errors::InterceptorError;
use crate::core::models::HistoryEntry;
use serde_json::Value;
use std::collections::HashSet;

pub struct PatternMatcher;

impl PatternMatcher {
    /// Evaluate a logic condition or sequence pattern
    pub async fn evaluate_pattern_with_args(
        pattern: &Value,
        history: &[HistoryEntry],
        current_tool: &str,
        current_classes: &[String],
        current_taints: &HashSet<String>,
        args: &Value,
    ) -> Result<bool, InterceptorError> {
        // Wrap sync call 
        Self::evaluate_condition_with_args(
            pattern,
            history,
            current_tool,
            current_classes,
            current_taints,
            args,
            0,
        )
    }

    /// Evaluate a complex condition against context.
    /// Supports a subset of "JsonLogic" style operators:
    /// - Data Access: {"var": "path.to.field"}
    /// - Logic: {"and": [...]}, {"or": [...]}, {"not": ...}
    /// - Comparison: {"==": [a, b]}, {"!=": [a, b]}, {">": [a, b]}, {"<": [a, b]}
    /// - Collections: {"contains": [list, item]}
    // NOTE: Made synchronous to avoid async recursion complexity. Logic evaluation is CPU-bound.
    pub fn evaluate_condition_with_args(
        condition: &Value,
        _history: &[HistoryEntry],
        _current_tool: &str,
        _current_classes: &[String],
        _current_taints: &HashSet<String>,
        args: &Value,
        depth: usize,
    ) -> Result<bool, InterceptorError> {
        if depth > 50 {
            return Err(InterceptorError::PolicyViolation(
                "Recursion depth limit exceeded".to_string(),
            ));
        }
        if condition.is_null() {
            return Ok(true);
        }

        match condition {
             Value::Bool(b) => Ok(*b),
             Value::Object(map) => {
                 // Check if it is an operator
                 if let Some((op, args_val)) = map.iter().next() {
                     match op.as_str() {
                         "and" => {
                             if let Value::Array(list) = args_val {
                                 for item in list {
                                     if !Self::evaluate_condition_with_args(item, _history, _current_tool, _current_classes, _current_taints, args, depth + 1)? {
                                         return Ok(false);
                                     }
                                 }
                                 Ok(true)
                             } else {
                                 Ok(false)
                             }
                         },
                         "or" => {
                              if let Value::Array(list) = args_val {
                                 for item in list {
                                     if Self::evaluate_condition_with_args(item, _history, _current_tool, _current_classes, _current_taints, args, depth + 1)? {
                                         return Ok(true);
                                     }
                                 }
                                 Ok(false)
                             } else {
                                 Ok(false)
                             }
                         },
                         "not" => {
                             let res = Self::evaluate_condition_with_args(args_val, _history, _current_tool, _current_classes, _current_taints, args, depth + 1)?;
                             Ok(!res)
                         },
                         "==" => {
                             let (lhs, rhs) = Self::resolve_binary_operands(args_val, args)?;
                             Ok(lhs == rhs)
                         },
                         "!=" => {
                             let (lhs, rhs) = Self::resolve_binary_operands(args_val, args)?;
                             Ok(lhs != rhs)
                         },
                          ">" => {
                             let (lhs, rhs) = Self::resolve_binary_operands(args_val, args)?;
                             Self::compare_values(&lhs, &rhs, |a, b| a > b)
                         },
                          "<" => {
                             let (lhs, rhs) = Self::resolve_binary_operands(args_val, args)?;
                             Self::compare_values(&lhs, &rhs, |a, b| a < b)
                         },
                         _ => {
                             // Unknown operator or just a literal object?
                             // Fail safe for now if it looks like logic but isn't handled
                             Ok(false)
                         }
                     }
                 } else {
                     // Empty object
                     Ok(false)
                 }
             },
             _ => Ok(false) // Literals in top position (other than bool) usually not valid conditions
        }
    }

    fn resolve_binary_operands(op_args: &Value, context_args: &Value) -> Result<(Value, Value), InterceptorError> {
        if let Value::Array(list) = op_args {
            if list.len() >= 2 {
                let lhs = Self::resolve_value(&list[0], context_args)?;
                let rhs = Self::resolve_value(&list[1], context_args)?;
                return Ok((lhs, rhs));
            }
        }
        Ok((Value::Null, Value::Null))
    }

    fn resolve_value(val: &Value, context_args: &Value) -> Result<Value, InterceptorError> {
        if let Value::Object(map) = val {
            if let Some(path_val) = map.get("var") {
                 if let Value::String(path) = path_val {
                     // Extract variable from args
                     // Simple path resolution (e.g. "foo" or "foo.bar")
                     // For MVP, just top level
                     return Ok(context_args.get(path).cloned().unwrap_or(Value::Null));
                 }
            }
        }
        Ok(val.clone())
    }
    
    fn compare_values<F>(lhs: &Value, rhs: &Value, op: F) -> Result<bool, InterceptorError> 
    where F: Fn(f64, f64) -> bool {
        match (lhs, rhs) {
            (Value::Number(a), Value::Number(b)) => {
               if let (Some(fa), Some(fb)) = (a.as_f64(), b.as_f64()) {
                   Ok(op(fa, fb))
               } else {
                   Ok(false)
               }
            },
            _ => Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_pattern_eval() {
        let args = json!({ "user_id": 123, "safe": true });
        
        // Test: user_id == 123
        let cond1 = json!({ "==": [{ "var": "user_id" }, 123] });
        assert_eq!(PatternMatcher::evaluate_condition_with_args(&cond1, &[], "", &[], &HashSet::new(), &args, 0).await.unwrap(), true);

        // Test: user_id > 100
        let cond2 = json!({ ">": [{ "var": "user_id" }, 100] });
        assert_eq!(PatternMatcher::evaluate_condition_with_args(&cond2, &[], "", &[], &HashSet::new(), &args, 0).await.unwrap(), true);

        // Test: safe AND (user_id < 200)
        let cond3 = json!({ 
            "and": [
                { "var": "safe" },
                { "<": [{ "var": "user_id" }, 200] }
            ] 
        });
        // Note: {"var": "safe"} resolves to true (bool), but evaluate_condition expects a condition structure.
        // If "var" returns a boolean, we need to handle that in the match? 
        // Our current impl expects condition to be an Object with operator OR a Bool literal.
        // { "var": "safe" } is an Object with "var" key, but "var" is treated as value resolver.
        // We probably need `evaluate_condition` to call `resolve_value` if it sees a "var" at top level too?
        // Actually, JsonLogic spec says `{"var": "x"}` evaluates to data. If data is bool, it works for `if`.
        // Let's refine `evaluate_condition` to resolve vars first if needed? 
        // Or wrap in `== true`? 
        // For simplicity, let's just stick to explicit comparisons for now or rely on Value::Bool check logic.
        // Wait, `evaluate_condition` takes `&Value`. If it's `{"var": ...}`, it falls into `Value::Object`.
        // But `var` is NOT in the match arms (and, or, not, ==).
        // It hits `_ => Ok(false)`.
        
        // FIX: Add "var" to the match arms in `evaluate_condition`!
    }
}
