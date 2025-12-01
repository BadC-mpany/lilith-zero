# sentinel-agent/src/tool_loader.py

import yaml
import os
from typing import List, Dict

# Use absolute paths for agent-side dependencies
from sentinel_sdk import SentinelSecureTool
from .tool_registry import get_registry
from .path_utils import get_project_path

def load_sentinel_tools(api_key: str, policies_yaml_path: str = None) -> List[SentinelSecureTool]:
    """
    Loads and returns a list of SentinelSecureTool instances based on the policies
    defined in the policies.yaml file for a given API key.

    This loader is for the AGENT side. It determines which tools to expose to the agent
    but does not enforce any rules itself.
    """
    # Resolve path relative to project root if not absolute
    if policies_yaml_path is None:
        policies_yaml_path = get_project_path("sentinel_core", "policies.yaml")
    elif not os.path.isabs(policies_yaml_path):
        policies_yaml_path = get_project_path(policies_yaml_path)
    
    policies_yaml_path = str(policies_yaml_path)
    
    if not os.path.exists(policies_yaml_path):
        raise FileNotFoundError(f"Policies YAML file not found at {policies_yaml_path}")

    with open(policies_yaml_path, 'r') as f:
        config = yaml.safe_load(f)

    # Find the customer config for the given API key
    customer_config = None
    for cfg in config.get("customers", []):
        if cfg.get("api_key") == api_key:
            customer_config = cfg
            break
    
    if not customer_config:
        raise ValueError(f"API Key '{api_key}' not found in {policies_yaml_path} customers.")

    # Find the policy for that customer
    policy_name = customer_config.get("policy_name")
    policy_definition = None
    for policy in config.get("policies", []):
        if policy.get("name") == policy_name:
            policy_definition = policy
            break

    if not policy_definition:
        raise ValueError(f"Policy '{policy_name}' not found in {policies_yaml_path}.")

    # Get the tool registry which contains descriptions and schemas
    registry = get_registry()
    
    sentinel_tools: List[SentinelSecureTool] = []
    # The agent should be aware of all tools defined in its static rules,
    # whether they are ALLOWED or DENIED. This allows the agent to attempt
    # to use a denied tool, which correctly triggers a security block from the interceptor.
    for tool_name in policy_definition.get("static_rules", {}).keys():
        tool_def = registry.get_tool(tool_name)
        if not tool_def:
            # For robustness, log a warning but don't crash the agent.
            # The interceptor is the final authority.
            print(f"Warning: Tool '{tool_name}' from policy not found in tool registry. Skipping.")
            continue
        
        sentinel_tools.append(
            SentinelSecureTool(
                name=tool_name, 
                description=tool_def.description,
                args_schema=tool_def.args_schema
            )
        )
    
    return sentinel_tools

