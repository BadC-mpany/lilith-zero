use lilith_zero::engine::pattern_matcher::PatternMatcher;
use lilith_zero::engine_core::models::{LogicCondition, LogicValue};
use proptest::prelude::*;
use std::collections::HashSet;
use tokio::runtime::Runtime;

proptest! {
    #[test]
    fn test_evaluate_pattern_no_panic(
        val_str in "\\PC*",
        user_id in 0..1000u64
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let args = serde_json::json!({
                "user_id": user_id,
                "name": val_str
            });

            // Condition: user_id == <generated_id>
            let cond = LogicCondition::Eq(vec![
                LogicValue::Var { var: "user_id".to_string() },
                LogicValue::Num(user_id as f64)
            ]);

            let res = PatternMatcher::evaluate_pattern_with_args(
                 &cond, &[], "test_tool", &[], &HashSet::new(), &args
            ).await;

            assert!(res.is_ok());
            assert!(res.unwrap()); // Should match
        });
    }

    #[test]
    fn test_evaluate_pattern_mismatch(
        user_id in 0..1000u64
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let args = serde_json::json!({
                "user_id": user_id + 1, // Mismatch
            });

            let cond = LogicCondition::Eq(vec![
                LogicValue::Var { var: "user_id".to_string() },
                LogicValue::Num(user_id as f64)
            ]);

            let res = PatternMatcher::evaluate_pattern_with_args(
                 &cond, &[], "test_tool", &[], &HashSet::new(), &args
            ).await;

            assert!(res.is_ok());
            assert!(!res.unwrap()); // Should NOT match
        });
    }
}
