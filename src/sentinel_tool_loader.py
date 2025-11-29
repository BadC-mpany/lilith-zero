import yaml
import os
from typing import List, Dict
from .sentinel_sdk import SentinelSecureTool
from .interceptor_service import PolicyDefinition, CustomerConfig
from .tool_schemas import TOOL_SCHEMAS # Import the schemas


def load_sentinel_tools(api_key: str, policies_yaml_path: str = "policies.yaml") -> List[SentinelSecureTool]:
    """
    Loads and returns a list of SentinelSecureTool instances based on the policies
    defined in the policies.yaml file for a given API key.
    """
    if not os.path.exists(policies_yaml_path):
        raise FileNotFoundError(f"Policies YAML file not found at {policies_yaml_path}")

    with open(policies_yaml_path, 'r') as f:
        config = yaml.safe_load(f)

    all_customers: Dict[str, CustomerConfig] = {}
    for customer_data in config.get("customers", []):
        key = customer_data.pop("api_key")
        all_customers[key] = CustomerConfig(**customer_data)

    all_policies: Dict[str, PolicyDefinition] = {}
    for policy_data in config.get("policies", []):
        policy_name = policy_data["name"]
        all_policies[policy_name] = PolicyDefinition(**policy_data)

    customer_config = all_customers.get(api_key)
    if not customer_config:
        raise ValueError(f"API Key '{api_key}' not found in policies.yaml customers.")

    policy_definition = all_policies.get(customer_config.policy_name)
    if not policy_definition:
        raise ValueError(f"Policy '{customer_config.policy_name}' not found in policies.yaml.")

    sentinel_tools: List[SentinelSecureTool] = []
    # Instantiate tools for ALL static rules, not just ALLOW.
    # This is so the agent is aware of the tool and can attempt to use it,
    # allowing the Interceptor to demonstrate a DENY rule.
    for tool_name in policy_definition.static_rules.keys():
        # Get the corresponding schema for the tool
        tool_schema = TOOL_SCHEMAS.get(tool_name)
        if not tool_schema:
            raise ValueError(f"No input schema found for tool '{tool_name}'. Please define it in tool_schemas.py.")
        
        # The description for the tool itself should be generic
        description = f"A secure tool for {tool_name}. Input should be a JSON object with keys: {list(tool_schema.__fields__.keys())}"

        sentinel_tools.append(
            SentinelSecureTool(
                name=tool_name, 
                description=description,
                args_schema=tool_schema # Assign the schema
            )
        )
    
    return sentinel_tools

