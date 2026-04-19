use lilith_zero::engine::pattern_matcher::PatternMatcher;
use lilith_zero::engine_core::models::{LogicCondition, LogicValue};
use proptest::prelude::*;
use std::collections::HashSet;
use tokio::runtime::Runtime;

proptest! {
    // Miri is slow, so we scale down the number of cases.
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 1 } else { 100 },
        .. ProptestConfig::default()
    })]

    #[test]
    fn test_evaluate_pattern_no_panic(
        val_str in "\\PC*",
        user_id in 0..1000u64
    ) {
        if cfg!(miri) { eprintln!("Running Miri: test_evaluate_pattern_no_panic"); }
        let args = serde_json::json!({
            "user_id": user_id,
            "name": val_str
        });

        // Condition: user_id == <generated_id>
        let cond = LogicCondition::Eq(vec![
            LogicValue::Var { var: "user_id".to_string() },
            LogicValue::Num(user_id as f64)
        ]);

        // Call sync evaluator directly to avoid Tokio overhead under Miri
        let res = PatternMatcher::evaluate_condition_with_args(
             &cond, &[], "test_tool", &[], &HashSet::new(), &args, 0
        );

        assert!(res.is_ok());
        assert!(res.unwrap()); // Should match
    }

    #[test]
    fn test_evaluate_pattern_mismatch(
        user_id in 0..1000u64
    ) {
        if cfg!(miri) { eprintln!("Running Miri: test_evaluate_pattern_mismatch"); }
        let args = serde_json::json!({
            "user_id": user_id + 1, // Mismatch
        });

        let cond = LogicCondition::Eq(vec![
            LogicValue::Var { var: "user_id".to_string() },
            LogicValue::Num(user_id as f64)
        ]);

        // Call sync evaluator directly to avoid Tokio overhead under Miri
        let res = PatternMatcher::evaluate_condition_with_args(
             &cond, &[], "test_tool", &[], &HashSet::new(), &args, 0
        );

        assert!(res.is_ok());
        assert!(!res.unwrap()); // Should NOT match
    }
}
