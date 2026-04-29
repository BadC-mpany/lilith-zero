import re

with open('src/engine_core/security_core.rs', 'r') as f:
    content = f.read()

# Add imports
content = content.replace('use crate::engine::evaluator::PolicyEvaluator;', 'use crate::engine::evaluator::PolicyEvaluator;\nuse crate::engine::cedar_evaluator::CedarEvaluator;\nuse crate::engine::yaml_to_cedar::CedarCompiler;\nuse crate::engine_core::path_utils::extract_and_canonicalize_paths;\nuse cedar_policy::Decision as CedarDecision;')

# Add cedar_evaluator to SecurityCore
content = content.replace('pub policy: Option<PolicyDefinition>,', 'pub policy: Option<PolicyDefinition>,\n    pub cedar_evaluator: Option<CedarEvaluator>,')

# Update SecurityCore::new
content = content.replace('policy: None,', 'policy: None,\n            cedar_evaluator: None,')

# Update SecurityCore::set_policy
set_policy_new = """    pub fn set_policy(&mut self, mut policy: PolicyDefinition) {
        if policy.protect_lethal_trifecta || self.config.protect_lethal_trifecta {
            info!("Lethal trifecta protection enabled - auto-injecting EXFILTRATION blocking rule");
            policy.taint_rules.push(PolicyRule {
                tool: None,
                tool_class: Some("EXFILTRATION".to_string()),
                action: "CHECK_TAINT".to_string(),
                tag: None,
                forbidden_tags: None,
                required_taints: Some(vec![
                    "ACCESS_PRIVATE".to_string(),
                    "UNTRUSTED_SOURCE".to_string(),
                ]),
                error: Some("Blocked by lethal trifecta protection".to_string()),
                pattern: None,
                exceptions: None,
            });
        }
        
        match CedarCompiler::compile(&policy) {
            Ok(policy_set) => {
                self.cedar_evaluator = Some(CedarEvaluator::new(policy_set));
                info!("Successfully compiled YAML policy to Cedar PolicySet");
            }
            Err(e) => {
                warn!("Failed to compile policy to Cedar: {}. Falling back to legacy evaluator.", e);
            }
        }
        
        self.policy = Some(policy);
    }"""
content = re.sub(r'pub fn set_policy\(&mut self, mut policy: PolicyDefinition\) \{.*?\n    \}', set_policy_new, content, flags=re.DOTALL)

with open('src/engine_core/security_core.rs', 'w') as f:
    f.write(content)
