# sentinel-core/interceptor/python/src/policy_loader.py

import yaml
import os
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Dict, List, Any, Optional

# --- Data Models ---

class PolicyRule(BaseModel):
    tool: Optional[str] = None
    tool_class: Optional[str] = None
    action: str
    tag: Optional[str] = None
    forbidden_tags: Optional[List[str]] = None
    error: Optional[str] = None
    pattern: Optional[Dict[str, Any]] = None

    def matches_tool(self, tool_name: str, tool_classes: List[str]) -> bool:
        if self.tool and self.tool == tool_name:
            return True
        if self.tool_class and self.tool_class in tool_classes:
            return True
        return False

class PolicyDefinition(BaseModel):
    name: str
    static_rules: Dict[str, str]
    taint_rules: List[PolicyRule]

class CustomerConfig(BaseModel):
    owner: str
    mcp_upstream_url: str
    policy_name: str

# --- Loader Class ---

class PolicyLoaderSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    policies_yaml_path: str = "/app/policies.yaml"
    tool_registry_path: str = "/app/rule_maker/data/tool_registry.yaml"

class PolicyLoader:
    """
    Loads all security policies and tool classifications from YAML files.
    This is a simplified, security-focused loader for the trusted interceptor.
    It does NOT handle agent-side concerns like Pydantic schema generation.
    """
    def __init__(
        self,
        policies_path: str = None,
        tool_registry_path: str = None
    ):
        # Use environment variables if paths not provided
        settings = PolicyLoaderSettings()
        self.policies_path = policies_path or settings.policies_yaml_path
        self.tool_registry_path = tool_registry_path or settings.tool_registry_path
        self.customers: Dict[str, CustomerConfig] = {}
        self.policies: Dict[str, PolicyDefinition] = {}
        self.tool_classes: Dict[str, List[str]] = {}

        self._load_tool_registry(self.tool_registry_path)
        self._load_policies(self.policies_path)

    def _load_tool_registry(self, path: str):
        """Loads tool names and their security classes from the tool registry."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Tool registry not found at {path}")
        with open(path, 'r') as f:
            config = yaml.safe_load(f)
        
        tools_config = config.get("tools", {})
        for tool_name, tool_config in tools_config.items():
            self.tool_classes[tool_name] = tool_config.get("classes", [])

    def _load_policies(self, path: str):
        """Loads customer and policy definitions from the main policies file."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Policies YAML file not found at {path}")
        with open(path, 'r') as f:
            config = yaml.safe_load(f)

        for customer_data in config.get("customers", []):
            api_key = customer_data.pop("api_key")
            self.customers[api_key] = CustomerConfig(**customer_data)

        for policy_data in config.get("policies", []):
            policy_name = policy_data["name"]
            self.policies[policy_name] = PolicyDefinition(**policy_data)

    def get_customer_config(self, api_key: str) -> Optional[CustomerConfig]:
        return self.customers.get(api_key)

    def get_policy(self, policy_name: str) -> Optional[PolicyDefinition]:
        return self.policies.get(policy_name)

    def get_tool_classes(self, tool_name: str) -> List[str]:
        return self.tool_classes.get(tool_name, [])

# --- Singleton Instance ---

_policy_loader_instance: Optional[PolicyLoader] = None

def get_policy_loader() -> PolicyLoader:
    """Returns a singleton instance of the PolicyLoader."""
    global _policy_loader_instance
    if _policy_loader_instance is None:
        _policy_loader_instance = PolicyLoader()
    return _policy_loader_instance
