// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and


use crate::engine_core::errors::InterceptorError;
use crate::engine_core::models::{HistoryEntry, LogicCondition, LogicValue};
use serde_json::Value; // Needed for resolving runtime arguments
use std::collections::HashSet;

pub struct PatternMatcher;

impl PatternMatcher {
    #[must_use]
    pub async fn evaluate_pattern_with_args(
        pattern: &LogicCondition,
        history: &[HistoryEntry],
        current_tool: &str,
        current_classes: &[String],
        current_taints: &HashSet<String>,
        args: &Value,
    ) -> Result<bool, InterceptorError> {
        // Description: Executes the evaluate_pattern_with_args logic.
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

    #[must_use]
    pub fn evaluate_condition_with_args(
        condition: &LogicCondition,
        _history: &[HistoryEntry],
        _current_tool: &str,
        _current_classes: &[String],
        _current_taints: &HashSet<String>,
        args: &Value,
        depth: usize,
    ) -> Result<bool, InterceptorError> {
        // Description: Executes the evaluate_condition_with_args logic.
        if depth > 50 {
            return Err(InterceptorError::PolicyViolation(
                "Recursion depth limit exceeded".to_string(),
            ));
        }

        match condition {
            LogicCondition::Literal(b) => Ok(*b),

            LogicCondition::And(rules) => {
                for rule in rules {
                    if !Self::evaluate_condition_with_args(
                        rule,
                        _history,
                        _current_tool,
                        _current_classes,
                        _current_taints,
                        args,
                        depth + 1,
                    )? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }

            LogicCondition::Or(rules) => {
                for rule in rules {
                    if Self::evaluate_condition_with_args(
                        rule,
                        _history,
                        _current_tool,
                        _current_classes,
                        _current_taints,
                        args,
                        depth + 1,
                    )? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }

            LogicCondition::Not(rule) => {
                let res = Self::evaluate_condition_with_args(
                    rule,
                    _history,
                    _current_tool,
                    _current_classes,
                    _current_taints,
                    args,
                    depth + 1,
                )?;
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

    fn loose_eq(lhs: &Value, rhs: &Value) -> bool {
        // Description: Executes the loose_eq logic.
        if lhs == rhs {
            return true;
        }
        if let (Value::Number(a), Value::Number(b)) = (lhs, rhs) {
            if let (Some(fa), Some(fb)) = (a.as_f64(), b.as_f64()) {
                return (fa - fb).abs() < f64::EPSILON;
            }
        }
        false
    }

    fn evaluate_tool_args_match(spec: &Value, args: &Value) -> Result<bool, InterceptorError> {
        // Description: Executes the evaluate_tool_args_match logic.
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

    fn values_match(pattern: &Value, arg: &Value) -> bool {
        // Description: Executes the values_match logic.
        match (pattern, arg) {
            (Value::String(p), Value::String(a)) => Self::wildcard_match(p, a),
            (Value::Number(p), Value::Number(a)) => p == a,
            (Value::Bool(p), Value::Bool(a)) => p == a,
            (Value::Null, Value::Null) => true,
            (p, a) => p == a,
        }
    }

    #[must_use]
    pub(crate) fn wildcard_match(pattern: &str, text: &str) -> bool {
        let mut parts = pattern.split('*');

        let first_part = match parts.next() {
            Some(p) => p,
            None => return text.is_empty(), // pattern is empty -> exact match ""
        };

        if !text.starts_with(first_part) {
            return false;
        }

        let mut text_slice = &text[first_part.len()..];

        for part in parts {
            if part.is_empty() {
                continue;
            }

            match text_slice.find(part) {
                Some(idx) => {
                    text_slice = &text_slice[idx + part.len()..];
                }
                None => return false,
            }
        }



        if !pattern.contains('*') {
            return pattern == text;
        }

        let mut parts_rev = pattern.split('*');
        let prefix = parts_rev.next().unwrap_or("");
        if !text.starts_with(prefix) {
            return false;
        }

        let suffix = pattern.rsplit('*').next().unwrap_or("");
        if !text.ends_with(suffix) {
            return false;
        }

        if prefix.len() + suffix.len() > text.len() {
            return false;
        }
        let mut remainder = &text[prefix.len()..text.len() - suffix.len()];

        let inner_parts = pattern[prefix.len()..pattern.len() - suffix.len()].split('*');
        for part in inner_parts {
            if part.is_empty() {
                continue;
            }
            match remainder.find(part) {
                Some(idx) => remainder = &remainder[idx + part.len()..],
                None => return false,
            }
        }
        true
    }

    fn resolve_binary(
        operands: &[LogicValue],
        context_args: &Value,
    ) -> Result<(Value, Value), InterceptorError> {
        // Description: Executes the resolve_binary logic.
        if operands.len() < 2 {
            return Ok((Value::Null, Value::Null));
        }
        let lhs = Self::resolve_value(&operands[0], context_args)?;
        let rhs = Self::resolve_value(&operands[1], context_args)?;
        Ok((lhs, rhs))
    }

    fn resolve_value(val: &LogicValue, context_args: &Value) -> Result<Value, InterceptorError> {
        // Description: Executes the resolve_value logic.
        match val {
            LogicValue::Var { var } => Ok(context_args.get(var).cloned().unwrap_or(Value::Null)),
            LogicValue::Str(s) => Ok(Value::String(s.clone())),
            LogicValue::Num(n) => {
                if let Some(num) = serde_json::Number::from_f64(*n) {
                    Ok(Value::Number(num))
                } else {
                    Ok(Value::Null) // NaN or Inf
                }
            }
            LogicValue::Bool(b) => Ok(Value::Bool(*b)),
            LogicValue::Null => Ok(Value::Null),
            LogicValue::Object(v) => Ok(v.clone()),
            LogicValue::Array(arr) => Ok(Value::Array(arr.clone())),
        }
    }

    fn compare_num<F>(lhs: Value, rhs: Value, op: F) -> Result<bool, InterceptorError>
    where
        F: Fn(f64, f64) -> bool,
    {
        // Description: Executes the compare_num logic.
        match (lhs, rhs) {
            (Value::Number(a), Value::Number(b)) => {
                if let (Some(fa), Some(fb)) = (a.as_f64(), b.as_f64()) {
                    Ok(op(fa, fb))
                } else {
                    Ok(false)
                }
            }
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_pattern_eval_typed() {
        // Description: Executes the test_pattern_eval_typed logic.
        let args = json!({ "user_id": 123, "safe": true });

        let cond1 = LogicCondition::Eq(vec![
            LogicValue::Var {
                var: "user_id".to_string(),
            },
            LogicValue::Num(123.0),
        ]);

        assert!(PatternMatcher::evaluate_pattern_with_args(
            &cond1,
            &[],
            "",
            &[],
            &HashSet::new(),
            &args
        )
        .await
        .unwrap());

        let cond2 = LogicCondition::Gt(vec![
            LogicValue::Var {
                var: "user_id".to_string(),
            },
            LogicValue::Num(100.0),
        ]);

        assert!(PatternMatcher::evaluate_pattern_with_args(
            &cond2,
            &[],
            "",
            &[],
            &HashSet::new(),
            &args
        )
        .await
        .unwrap());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_wildcard_match_properties(pattern in "\\PC*", text in "\\PC*") {
            // Description: Executes the test_wildcard_match_properties logic.
            let _ = PatternMatcher::wildcard_match(&pattern, &text);
        }

        #[test]
        fn test_wildcard_match_identity(text in "\\PC*") {
            // Description: Executes the test_wildcard_match_identity logic.
            assert!(PatternMatcher::wildcard_match(&text, &text));
        }

        #[test]
        fn test_wildcard_match_star(text in "\\PC*") {
            // Description: Executes the test_wildcard_match_star logic.
            assert!(PatternMatcher::wildcard_match("*", &text));
        }
    }


    use proptest::strategy::{BoxedStrategy, Strategy};

    fn arb_logic_value() -> BoxedStrategy<LogicValue> {
        // Description: Executes the arb_logic_value logic.
        prop_oneof![
            Just(LogicValue::Null),
            any::<bool>().prop_map(LogicValue::Bool),
            any::<f64>().prop_map(LogicValue::Num),
            ".*".prop_map(LogicValue::Str),
            "[a-z]+".prop_map(|var| LogicValue::Var { var }),
        ]
        .boxed()
    }

    fn arb_logic_condition() -> impl Strategy<Value = LogicCondition> {
        // Description: Executes the arb_logic_condition logic.
        let val = arb_logic_value();

        let leaf = prop_oneof![
            Just(LogicCondition::Literal(true)),
            Just(LogicCondition::Literal(false)),
            prop::collection::vec(val.clone(), 2..3).prop_map(LogicCondition::Eq),
            prop::collection::vec(val.clone(), 2..3).prop_map(LogicCondition::Neq),
            prop::collection::vec(val.clone(), 2..3).prop_map(LogicCondition::Gt),
            prop::collection::vec(val.clone(), 2..3).prop_map(LogicCondition::Lt),
        ];

        leaf.prop_recursive(
            4,  // 4 levels deep
            64, // max size
            10, // items per collection
            |inner: proptest::strategy::BoxedStrategy<LogicCondition>| {
                prop_oneof![
                    prop::collection::vec(inner.clone(), 0..3).prop_map(LogicCondition::And),
                    prop::collection::vec(inner.clone(), 0..3).prop_map(LogicCondition::Or),
                    inner.prop_map(|c| LogicCondition::Not(Box::new(c))),
                ]
            },
        )
    }

    proptest! {
        #[test]
        fn test_pattern_eval_fuzz(
            cond in arb_logic_condition(),
            // We need a runtime to block on async
        ) {
            // Description: Executes the test_pattern_eval_fuzz logic.
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let args = serde_json::json!({});
                let _ = PatternMatcher::evaluate_pattern_with_args(
                    &cond, &[], "test", &[], &HashSet::new(), &args
                ).await;
            });
        }
    }
}
