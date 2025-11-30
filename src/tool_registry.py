"""
Tool Registry System - Single Source of Truth for Tool Definitions
Loads tools from rule_maker/tool_registry.yaml and provides:
- Tool metadata (description, classes)
- Dynamic Pydantic schema generation
- Tool name → classes mapping
"""

import yaml
import os
from typing import Dict, List, Any, Optional, Type
# Use pydantic v1 for LangChain compatibility
from langchain_core.pydantic_v1 import BaseModel, Field, create_model


class ToolDefinition:
    """Represents a single tool's complete definition."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.description = config.get("description", f"Tool: {name}")
        self.classes: List[str] = config.get("classes", [])
        self.auto_classified: bool = config.get("auto_classified", False)
        self.args_config: Dict[str, Any] = config.get("args", {})
        
        # Generate Pydantic schema dynamically
        self.args_schema = self._generate_schema()
    
    def _generate_schema(self) -> Type[BaseModel]:
        """Dynamically creates a Pydantic BaseModel from the args configuration."""
        if not self.args_config:
            # No arguments - create empty schema
            return create_model(f"{self.name.title()}Input")
        
        field_definitions = {}
        for arg_name, arg_config in self.args_config.items():
            arg_type = arg_config.get("type", "string")
            arg_desc = arg_config.get("description", f"Argument: {arg_name}")
            is_required = arg_config.get("required", True)
            
            # Map YAML types to Python types
            type_mapping = {
                "string": str,
                "int": int,
                "integer": int,
                "bool": bool,
                "boolean": bool,
                "float": float,
                "number": float,
            }
            
            python_type = type_mapping.get(arg_type.lower(), str)
            
            # Add Optional wrapper if not required
            if not is_required:
                python_type = Optional[python_type]
                field_definitions[arg_name] = (python_type, Field(default=None, description=arg_desc))
            else:
                field_definitions[arg_name] = (python_type, Field(description=arg_desc))
        
        # Create the model dynamically
        model = create_model(
            f"{self.name.title().replace('_', '')}Input",
            **field_definitions
        )
        
        return model


class ToolRegistry:
    """Central registry for all tool definitions."""
    
    def __init__(self, registry_path: str = "rule_maker/tool_registry.yaml"):
        self.registry_path = registry_path
        self.tools: Dict[str, ToolDefinition] = {}
        self._load_registry()
    
    def _load_registry(self):
        """Loads tool definitions from YAML file."""
        if not os.path.exists(self.registry_path):
            raise FileNotFoundError(
                f"Tool registry not found at {self.registry_path}. "
                "Please ensure the file exists."
            )
        
        with open(self.registry_path, 'r') as f:
            config = yaml.safe_load(f)
        
        tools_config = config.get("tools", {})
        for tool_name, tool_config in tools_config.items():
            self.tools[tool_name] = ToolDefinition(tool_name, tool_config)
    
    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """Returns tool definition by name."""
        return self.tools.get(name)
    
    def get_tool_classes(self, name: str) -> List[str]:
        """Returns the list of classes for a given tool name."""
        tool = self.get_tool(name)
        return tool.classes if tool else []
    
    def get_all_tool_names(self) -> List[str]:
        """Returns all registered tool names."""
        return list(self.tools.keys())
    
    def get_schema(self, name: str) -> Optional[Type[BaseModel]]:
        """Returns the Pydantic schema for a tool."""
        tool = self.get_tool(name)
        return tool.args_schema if tool else None


# Global registry instance
_registry: Optional[ToolRegistry] = None


def get_registry() -> ToolRegistry:
    """Returns the global tool registry instance (singleton pattern)."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry

