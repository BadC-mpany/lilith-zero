//! Pattern matching engine for dynamic rules.
//!
//! This module provides the `PatternMatcher` which evaluates strictly typed
//! logic conditions against the current tool call and session history.

use crate::core::errors::InterceptorError;
use crate::core::models::{HistoryEntry, LogicCondition, LogicValue};
use serde_json::Value; // Needed for resolving runtime arguments
use std::collections::HashSet;

pub struct PatternMatcher;

impl PatternMatcher {
    /// Evaluate a logic condition or sequence pattern
    pub async fn evaluate_pattern_with_args(
        pattern: &LogicCondition,
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
    // NOTE: Made synchronous to avoid async recursion complexity. Logic evaluation is CPU-bound.
    pub fn evaluate_condition_with_args(
        condition: &LogicCondition,
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

        match condition {
            LogicCondition::Literal(b) => Ok(*b),
            
            LogicCondition::And(rules) => {
                for rule in rules {
                    if !Self::evaluate_condition_with_args(rule, _history, _current_tool, _current_classes, _current_taints, args, depth + 1)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            
            LogicCondition::Or(rules) => {
                for rule in rules {
                    if Self::evaluate_condition_with_args(rule, _history, _current_tool, _current_classes, _current_taints, args, depth + 1)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            
            LogicCondition::Not(rule) => {
                let res = Self::evaluate_condition_with_args(rule, _history, _current_tool, _current_classes, _current_taints, args, depth + 1)?;
                Ok(!res)
            }
            
            LogicCondition::Eq(operands) => {
                let (lhs, rhs) = Self::resolve_binary(operands, args)?;
                Ok(Self::loose_eq(&lhs, &rhs))
            }
            LogicCondition::Neq(operands) => {
                let (lhs, rhs) = Self::resolve_binary(operands, args)?;
                Ok(!Self::loose_eq(&lhs, &rhs))
            }
            LogicCondition::Gt(operands) => {
                let (lhs, rhs) = Self::resolve_binary(operands, args)?;
                Self::compare_num(lhs, rhs, |a, b| a > b)
            }
            LogicCondition::Lt(operands) => {
                let (lhs, rhs) = Self::resolve_binary(operands, args)?;
                Self::compare_num(lhs, rhs, |a, b| a < b)
            }
            
            LogicCondition::ToolArgsMatch(match_spec) => {
                Self::evaluate_tool_args_match(match_spec, args)
            }
        }
    }

    /// Loose equality check (handles int vs float)
    fn loose_eq(lhs: &Value, rhs: &Value) -> bool {
        if lhs == rhs { return true; }
        if let (Value::Number(a), Value::Number(b)) = (lhs, rhs) {
            if let (Some(fa), Some(fb)) = (a.as_f64(), b.as_f64()) {
                return (fa - fb).abs() < f64::EPSILON;
            }
        }
        false
    }

    /// Check if tool arguments match the specification
    fn evaluate_tool_args_match(spec: &Value, args: &Value) -> Result<bool, InterceptorError> {
        let spec_map = spec.as_object().ok_or_else(|| {
            InterceptorError::PolicyViolation("tool_args_match spec must be an object".to_string())
        })?;

        for (key, pattern_val) in spec_map {
             let arg_val = match args.get(key) {
                 Some(v) => v,
                 None => return Ok(false), // Missing argument = No match
             };

             if !Self::values_match(pattern_val, arg_val) {
                 return Ok(false);
             }
        }
        Ok(true)
    }

    /// Compare pattern value with argument value (supporting wildcards for strings)
    fn values_match(pattern: &Value, arg: &Value) -> bool {
        match (pattern, arg) {
            (Value::String(p), Value::String(a)) => Self::wildcard_match(p, a),
            (Value::Number(p), Value::Number(a)) => p == a,
            (Value::Bool(p), Value::Bool(a)) => p == a,
            (Value::Null, Value::Null) => true,
            // Deep match for objects/arrays? For now simple equality (strict)
            (p, a) => p == a, 
        }
    }

    /// Simple matching with '*' support (Optimized: Zero Allocation)
    fn wildcard_match(pattern: &str, text: &str) -> bool {
        let mut parts = pattern.split('*');
        
        // 1. Check prefix (first part)
        let first_part = match parts.next() {
            Some(p) => p,
            None => return text.is_empty(), // pattern is empty -> exact match ""
        };
        
        if !text.starts_with(first_part) {
            return false;
        }
        
        let mut text_slice = &text[first_part.len()..];

        // 2. Check remaining parts
        for part in parts {
            if part.is_empty() {
                // Consecutive '*' or trailing '*'
                continue;
            }
            
            match text_slice.find(part) {
                Some(idx) => {
                    text_slice = &text_slice[idx + part.len()..];
                },
                None => return false,
            }
        }
        
        // 3. Suffix check logic
        // If the pattern ended with '*', we are good (loops skipped empty last part).
        // If the pattern did NOT end with '*', the last part in the loop MUST match the END of the string.
        // But our greedy loop just searched for the *first* occurrence.
        // Standard "A*B" logic: StartsWith A, EndsWith B.
        // My optimized loop finds 'B' *somewhere*.
        // Need to be careful. The split iterator Logic is safer but tricky to get right in one pass.
        // Let's stick to the Correct Logic but valid optimization:
        // Use `split` but don't collect.
        
        // Simpler correct implementation without collecting:
        // Re-implementing parts logic from scratch is risky for bugs.
        // Let's rely on standard iterator methods.
        
        if !pattern.contains('*') {
            return pattern == text;
        }

        let mut parts_rev = pattern.split('*');
        let prefix = parts_rev.next().unwrap_or(""); 
        if !text.starts_with(prefix) { return false; }
        
        let suffix = pattern.rsplit('*').next().unwrap_or("");
        if !text.ends_with(suffix) { return false; }
        
        if prefix.len() + suffix.len() > text.len() {
            return false;
        }
        let mut remainder = &text[prefix.len()..text.len()-suffix.len()];
        
        // Check inner parts
        let inner_parts = pattern[prefix.len()..pattern.len()-suffix.len()].split('*');
        for part in inner_parts {
             if part.is_empty() { continue; }
             match remainder.find(part) {
                 Some(idx) => remainder = &remainder[idx+part.len()..],
                 None => return false,
             }
        }
        true
    }

    fn resolve_binary(operands: &[LogicValue], context_args: &Value) -> Result<(Value, Value), InterceptorError> {
        if operands.len() < 2 {
            return Ok((Value::Null, Value::Null));
        }
        let lhs = Self::resolve_value(&operands[0], context_args)?;
        let rhs = Self::resolve_value(&operands[1], context_args)?;
        Ok((lhs, rhs))
    }

    fn resolve_value(val: &LogicValue, context_args: &Value) -> Result<Value, InterceptorError> {
        match val {
            LogicValue::Var { var } => {
                 Ok(context_args.get(var).cloned().unwrap_or(Value::Null))
            },
            LogicValue::Str(s) => Ok(Value::String(s.clone())),
            LogicValue::Num(n) => {
                // n is f64, serde_json::Number can correspond to f64
                if let Some(num) = serde_json::Number::from_f64(*n) {
                    Ok(Value::Number(num))
                } else {
                    Ok(Value::Null) // NaN or Inf
                }
            },
            LogicValue::Bool(b) => Ok(Value::Bool(*b)),
            LogicValue::Null => Ok(Value::Null),
            LogicValue::Object(v) => Ok(v.clone()),
            LogicValue::Array(arr) => Ok(Value::Array(arr.clone())),
        }
    }
    
    fn compare_num<F>(lhs: Value, rhs: Value, op: F) -> Result<bool, InterceptorError> 
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
    async fn test_pattern_eval_typed() {
        let args = json!({ "user_id": 123, "safe": true });
        
        // Test: user_id == 123
        // AST: Eq([Var("user_id"), Num(123.0)])
        let cond1 = LogicCondition::Eq(vec![
            LogicValue::Var { var: "user_id".to_string() },
            LogicValue::Num(123.0)
        ]);
        
        assert!(PatternMatcher::evaluate_pattern_with_args(&cond1, &[], "", &[], &HashSet::new(), &args).await.unwrap());

        // Test: user_id > 100
        let cond2 = LogicCondition::Gt(vec![
            LogicValue::Var { var: "user_id".to_string() },
            LogicValue::Num(100.0)
        ]);
        
        assert!(PatternMatcher::evaluate_pattern_with_args(&cond2, &[], "", &[], &HashSet::new(), &args).await.unwrap());
    }

}
