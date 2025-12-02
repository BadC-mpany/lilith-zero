# sentinel-core/mcp/src/tool_registry_loader.py

import os
import yaml
import logging
from typing import Dict, Any, List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore', env_prefix='')
    tool_registry_path: str = "/app/rule_maker/data/tool_registry.yaml"

    def __init__(self, **kwargs):
        # Override defaults with environment variables if they exist
        env_kwargs = {}
        if "TOOL_REGISTRY_PATH" in os.environ:
            env_kwargs["tool_registry_path"] = os.environ["TOOL_REGISTRY_PATH"]
        
        # Also try to find the file dynamically if not set
        if not env_kwargs.get("tool_registry_path") and "TOOL_REGISTRY_PATH" not in os.environ:
            # Try to find tool_registry.yaml relative to common locations
            script_dir = os.environ.get("SENTINEL_SCRIPT_DIR")
            if script_dir:
                candidate_path = os.path.join(script_dir, "rule_maker", "data", "tool_registry.yaml")
                if os.path.exists(candidate_path):
                    env_kwargs["tool_registry_path"] = candidate_path
        
        # Merge environment variables with kwargs
        merged_kwargs = {**env_kwargs, **kwargs}
        super().__init__(**merged_kwargs)


settings = Settings()


def convert_yaml_type_to_json_schema_type(yaml_type: str) -> Dict[str, Any]:
    """Convert YAML type to JSON Schema type."""
    type_mapping = {
        "string": "string",
        "int": "integer",
        "integer": "integer",
        "bool": "boolean",
        "boolean": "boolean",
        "float": "number",
        "number": "number",
        "array": "array",
    }
    return {"type": type_mapping.get(yaml_type.lower(), "string")}


def convert_tool_to_mcp_format(tool_name: str, tool_config: Dict[str, Any]) -> Dict[str, Any]:
    """Convert YAML tool definition to MCP JSON Schema format."""
    description = tool_config.get("description", f"Tool: {tool_name}")
    args_config = tool_config.get("args", {})
    
    # Build JSON Schema properties
    properties = {}
    required = []
    
    for arg_name, arg_config in args_config.items():
        arg_type = arg_config.get("type", "string")
        arg_desc = arg_config.get("description", f"Argument: {arg_name}")
        is_required = arg_config.get("required", True)
        
        # Convert type
        json_schema_type = convert_yaml_type_to_json_schema_type(arg_type)
        
        # Handle array type specially
        if arg_type.lower() == "array":
            json_schema_type["items"] = {"type": "string"}
        
        properties[arg_name] = {
            **json_schema_type,
            "description": arg_desc
        }
        
        if is_required:
            required.append(arg_name)
    
    # Build inputSchema
    input_schema = {
        "type": "object",
        "properties": properties
    }
    
    if required:
        input_schema["required"] = required
    
    return {
        "name": tool_name,
        "description": description,
        "inputSchema": input_schema
    }


class ToolRegistryLoader:
    """Loads and caches tool definitions from tool_registry.yaml for MCP server."""
    
    def __init__(self, registry_path: Optional[str] = None):
        self.registry_path = registry_path or settings.tool_registry_path
        self._tools_cache: Optional[List[Dict[str, Any]]] = None
        self._tools_dict: Dict[str, Dict[str, Any]] = {}
        self._load_registry()
    
    def _load_registry(self):
        """Load tool definitions from YAML file and convert to MCP format."""
        if not os.path.exists(self.registry_path):
            logger.warning(f"Tool registry not found at {self.registry_path}, using empty registry")
            self._tools_cache = []
            return
        
        try:
            with open(self.registry_path, 'r') as f:
                config = yaml.safe_load(f)
            
            tools_config = config.get("tools", {})
            mcp_tools = []
            
            for tool_name, tool_config in tools_config.items():
                mcp_tool = convert_tool_to_mcp_format(tool_name, tool_config)
                mcp_tools.append(mcp_tool)
                self._tools_dict[tool_name] = tool_config
            
            self._tools_cache = mcp_tools
            logger.info(f"Loaded {len(mcp_tools)} tools from registry")
            
        except Exception as e:
            logger.error(f"Error loading tool registry: {e}")
            self._tools_cache = []
    
    def get_tools_list(self) -> List[Dict[str, Any]]:
        """Returns list of tools in MCP format."""
        return self._tools_cache or []
    
    def get_tool_config(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Returns raw tool config by name."""
        return self._tools_dict.get(tool_name)
    
    def tool_exists(self, tool_name: str) -> bool:
        """Check if a tool exists in the registry."""
        return tool_name in self._tools_dict


# Global singleton instance
_registry_loader_instance: Optional[ToolRegistryLoader] = None


def get_tool_registry_loader() -> ToolRegistryLoader:
    """Returns a singleton instance of the ToolRegistryLoader."""
    global _registry_loader_instance
    if _registry_loader_instance is None:
        _registry_loader_instance = ToolRegistryLoader()
    return _registry_loader_instance

