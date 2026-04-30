#!/usr/bin/env python3
import yaml
import json
import argparse
import subprocess
import os
import sys

# Default values for your environment
DEFAULT_BOT_ID = "c0b26c67-1544-f111-bec6-7c1e52fad898"
DEFAULT_ENV_ID = "97bac1f2-0f6c-e8f3-8e7d-3d3752a8c84a"

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running command: {cmd}")
        print(result.stderr)
        return None
    return result.stdout

def extract_tools(bot_id, environment_id, output_path):
    temp_yaml = f"temp_{bot_id}.yaml"
    print(f"[*] Extracting template for bot {bot_id} in environment {environment_id}...")
    
    # Use dnx for Fedora compatibility as per your preference
    cmd = (f"dnx Microsoft.PowerApps.CLI.Tool --yes -- copilot extract-template "
           f"--bot {bot_id} --environment {environment_id} --templateFileName {temp_yaml}")
    
    out = run_command(cmd)
    if out is None or not os.path.exists(temp_yaml):
        print("[!] Failed to extract template.")
        return

    print("[*] Parsing template YAML...")
    try:
        with open(temp_yaml, 'r') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"[!] YAML parse error: {e}")
        return

    tools = []
    
    # Heuristic schemas for common standard connectors.
    # In a full production setup, these could be pulled from connector OpenAPI specs.
    COMMON_SCHEMAS = {
        "GetItemWithOrganization": {
            "type": "object",
            "properties": {
                "entityName": {"type": "string", "description": "The name of the entity"},
                "itemId": {"type": "string", "description": "The ID of the record"}
            },
            "required": ["entityName", "itemId"]
        },
        "DeleteEmail_V2": {
            "type": "object",
            "properties": {
                "messageId": {"type": "string", "description": "The ID of the email to delete"}
            },
            "required": ["messageId"]
        },
        "DirectReports_V2": {
            "type": "object",
            "properties": {
                "userPrincipalName": {"type": "string", "description": "UPN of the user"}
            },
            "required": ["userPrincipalName"]
        },
        "DeleteItem": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "ID of the row to delete"}
            },
            "required": ["id"]
        },
        "ContactDeleteItem_V2": {
            "type": "object",
            "properties": {
                "contactId": {"type": "string", "description": "ID of the contact"}
            },
            "required": ["contactId"]
        }
    }

    # Extract components which represent tool actions
    components = data.get('components', [])
    if isinstance(components, list):
        pass
    elif isinstance(components, dict):
        components = [components]
    else:
        components = []
        
    for comp in components:
        dialog = comp.get('dialog', {})
        if dialog.get('kind') == 'TaskDialog':
            action = dialog.get('action', {})
            op_id = action.get('operationId')
            display_name = dialog.get('modelDisplayName', op_id)
            description = dialog.get('modelDescription', '')
            
            tool_name = op_id if op_id else dialog.get('modelDisplayName', 'unknown')
            
            tool = {
                "name": tool_name,
                "description": description,
                "inputSchema": COMMON_SCHEMAS.get(op_id, {
                    "type": "object",
                    "properties": {},
                    "required": []
                })
            }
            tools.append(tool)

    output_json = {
        "agent_id": bot_id,
        "tools": tools
    }

    final_path = os.path.join(output_path, "tools.json")
    with open(final_path, 'w') as f:
        json.dump(output_json, f, indent=2)
    
    print(f"[+] Successfully wrote {len(tools)} tools to {final_path}")
    
    # Cleanup
    if os.path.exists(temp_yaml):
        os.remove(temp_yaml)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract Copilot Studio tools to tools.json")
    parser.add_argument("--bot", default=DEFAULT_BOT_ID, help=f"Bot ID (default: {DEFAULT_BOT_ID})")
    parser.add_argument("--environment", default=DEFAULT_ENV_ID, help=f"Environment ID (default: {DEFAULT_ENV_ID})")
    parser.add_argument("--output_path", default="./", help="Output directory (default: ./)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.output_path):
        os.makedirs(args.output_path)
        
    extract_tools(args.bot, args.environment, args.output_path)
