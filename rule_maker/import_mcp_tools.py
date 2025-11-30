"""
Import tools from MCP (Model Context Protocol) format and add to tool registry.

MCP Tools File Format:
The input should be a JSON file with an array of tool definitions.
Each tool follows the MCP schema format:

```json
{
  "tools": [
    {
      "name": "tool_name",
      "description": "What the tool does",
      "inputSchema": {
        "type": "object",
        "properties": {
          "arg_name": {
            "type": "string",
            "description": "Argument description"
          }
        },
        "required": ["arg_name"]
      }
    }
  ]
}
```

This format is compatible with MCP server tool definitions and can be easily
exported from MCP stores or server implementations.
"""

import json
import yaml
import os
import sys
from typing import List, Dict, Any
from classifier import classify_tool_with_llm
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()


def load_mcp_tools(mcp_file_path: str) -> List[Dict[str, Any]]:
    """
    Load tools from MCP JSON file.
    
    Expected format: {"tools": [{name, description, inputSchema}, ...]}
    """
    with open(mcp_file_path, 'r') as f:
        data = json.load(f)
    
    if "tools" not in data:
        raise ValueError("MCP file must contain 'tools' array")
    
    return data["tools"]


def convert_json_schema_to_yaml_args(input_schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert MCP JSON Schema inputSchema to our YAML args format.
    
    Input (MCP format):
        {
          "type": "object",
          "properties": {
            "query": {"type": "string", "description": "Search query"},
            "limit": {"type": "integer", "description": "Max results"}
          },
          "required": ["query"]
        }
    
    Output (our format):
        {
          "query": {"type": "string", "description": "Search query", "required": true},
          "limit": {"type": "integer", "description": "Max results", "required": false}
        }
    """
    if not input_schema or input_schema.get("type") != "object":
        return {}
    
    properties = input_schema.get("properties", {})
    required_fields = set(input_schema.get("required", []))
    
    args = {}
    for arg_name, arg_spec in properties.items():
        arg_type = arg_spec.get("type", "string")
        arg_desc = arg_spec.get("description", f"Argument: {arg_name}")
        
        args[arg_name] = {
            "type": arg_type,
            "description": arg_desc,
            "required": arg_name in required_fields
        }
    
    return args


def import_tools_to_registry(
    mcp_file_path: str,
    registry_path: str = "rule_maker/tool_registry.yaml",
    api_key: str = None,
    model: str = "gpt-4o-mini",
    max_examples_per_class: int = 2,
    dry_run: bool = False
):
    """
    Import tools from MCP file and append to tool registry.
    
    Args:
        mcp_file_path: Path to MCP tools JSON file
        registry_path: Path to tool_registry.yaml
        api_key: OpenAI API key for classification
        model: LLM model to use for classification
        max_examples_per_class: Max examples to show classifier per class
        dry_run: If True, print what would be added without modifying file
    
    Returns:
        Dict with statistics: {added, skipped, errors}
    """
    # Load MCP tools
    print(f"Loading tools from {mcp_file_path}...")
    mcp_tools = load_mcp_tools(mcp_file_path)
    print(f"Found {len(mcp_tools)} tools in MCP file\n")
    
    # Load existing registry
    if os.path.exists(registry_path):
        with open(registry_path, 'r') as f:
            registry = yaml.safe_load(f) or {}
    else:
        registry = {}
    
    if "tools" not in registry:
        registry["tools"] = {}
    
    existing_tools = registry["tools"]
    
    stats = {"added": 0, "skipped": 0, "errors": 0}
    new_tools = {}
    
    for i, mcp_tool in enumerate(mcp_tools, 1):
        tool_name = mcp_tool.get("name")
        tool_description = mcp_tool.get("description", "")
        input_schema = mcp_tool.get("inputSchema", {})
        
        if not tool_name:
            print(f"⚠️  Skipping tool {i}: missing name")
            stats["errors"] += 1
            continue
        
        # Check if tool already exists
        if tool_name in existing_tools:
            print(f"⏭️  Skipping {tool_name}: already in registry")
            stats["skipped"] += 1
            continue
        
        print(f"🔍 [{i}/{len(mcp_tools)}] Classifying: {tool_name}")
        print(f"   Description: {tool_description[:80]}...")
        
        try:
            # Classify tool
            classification_result = classify_tool_with_llm(
                tool_name=tool_name,
                tool_description=tool_description,
                max_examples_per_class=max_examples_per_class,
                api_key=api_key,
                model=model
            )
            
            classes = classification_result["classes"]
            reasoning = classification_result.get("reasoning", "")
            
            print(f"   ✅ Classes: {', '.join(classes)}")
            print(f"   💭 Reasoning: {reasoning[:100]}...")
            
            # Convert args format
            args = convert_json_schema_to_yaml_args(input_schema)
            
            # Build tool entry
            tool_entry = {
                "description": tool_description,
                "classes": classes,
                "auto_classified": True,
                "args": args
            }
            
            new_tools[tool_name] = tool_entry
            stats["added"] += 1
            print()
            
        except Exception as e:
            print(f"   ❌ Error classifying {tool_name}: {e}")
            stats["errors"] += 1
            print()
            continue
    
    # Summary
    print("\n" + "="*80)
    print("IMPORT SUMMARY")
    print("="*80)
    print(f"✅ Added: {stats['added']}")
    print(f"⏭️  Skipped (already exists): {stats['skipped']}")
    print(f"❌ Errors: {stats['errors']}")
    print(f"📊 Total processed: {len(mcp_tools)}")
    print("="*80)
    
    if dry_run:
        print("\n🔍 DRY RUN - No files were modified")
        print("\nTools that would be added:")
        print(yaml.dump({"tools": new_tools}, default_flow_style=False, sort_keys=False))
        return stats
    
    # Append new tools to registry
    if new_tools:
        registry["tools"].update(new_tools)
        
        # Write back to file
        with open(registry_path, 'w') as f:
            yaml.dump(registry, f, default_flow_style=False, sort_keys=False)
        
        print(f"\n✅ Successfully updated {registry_path}")
        print(f"   Added {stats['added']} new tools")
    else:
        print("\n⚠️  No new tools to add")
    
    return stats


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Import MCP tools and classify them into security classes"
    )
    parser.add_argument(
        "mcp_file",
        help="Path to MCP tools JSON file"
    )
    parser.add_argument(
        "--registry",
        default="rule_maker/tool_registry.yaml",
        help="Path to tool registry YAML (default: rule_maker/tool_registry.yaml)"
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="LLM model to use for classification (default: gpt-4o-mini)"
    )
    parser.add_argument(
        "--max-examples",
        type=int,
        default=2,
        help="Max example tools per class to show classifier (default: 2)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be added without modifying files"
    )
    
    args = parser.parse_args()
    
    # Check if API key is available (will be loaded from .env)
    if not os.getenv("OPENROUTER_API_KEY"):
        print("❌ ERROR: OPENROUTER_API_KEY not set in .env file")
        print("\nAdd to your .env file:")
        print("  OPENROUTER_API_KEY=sk-or-your-key-here")
        sys.exit(1)
    
    # Get API key (already loaded from .env)
    api_key = os.getenv("OPENROUTER_API_KEY")
    
    # Check if MCP file exists
    if not os.path.exists(args.mcp_file):
        print(f"❌ ERROR: MCP file not found: {args.mcp_file}")
        sys.exit(1)
    
    print(f"\n{'='*80}")
    print("MCP TOOLS IMPORT & CLASSIFICATION")
    print(f"{'='*80}\n")
    print(f"📁 MCP File: {args.mcp_file}")
    print(f"📋 Registry: {args.registry}")
    print(f"🤖 Model: {args.model}")
    print(f"📚 Max examples per class: {args.max_examples}")
    if args.dry_run:
        print(f"🔍 Mode: DRY RUN (no files will be modified)")
    print()
    
    # Run import
    import_tools_to_registry(
        mcp_file_path=args.mcp_file,
        registry_path=args.registry,
        api_key=api_key,
        model=args.model,
        max_examples_per_class=args.max_examples,
        dry_run=args.dry_run
    )

