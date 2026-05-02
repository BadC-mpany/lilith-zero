#!/usr/bin/env python3
import yaml
import json
import argparse
import subprocess
import os
import sys

# New defaults from your environment
DEFAULT_ENV_ID = "98e2f7d2-c1d3-4410-b87f-2396f157975f"
DEFAULT_BOTS = ["77236ced-1146-f111-bec6-7ced8d71fac9"]

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running command: {cmd}")
        print(result.stderr)
        return None
    return result.stdout

def extract_for_bot(bot_id, environment_id):
    temp_yaml = f"temp_{bot_id}.yaml"
    print(f"[*] Extracting template for bot {bot_id}...")
    
    cmd = (f"dnx Microsoft.PowerApps.CLI.Tool --yes -- copilot extract-template "
           f"--bot {bot_id} --environment {environment_id} --templateFileName {temp_yaml}")
    
    out = run_command(cmd)
    if out is None or not os.path.exists(temp_yaml):
        print(f"[!] Failed to extract template for {bot_id}.")
        return None

    print(f"[*] Parsing template for {bot_id}...")
    try:
        with open(temp_yaml, 'r') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"[!] YAML parse error for {bot_id}: {e}")
        return None
    finally:
        if os.path.exists(temp_yaml):
            os.remove(temp_yaml)

    tools = []
    # Extract components which represent tool actions
    components = data.get('components', [])
    if isinstance(components, dict):
        components = [components]
    
    for comp in components:
        # Support for DialogComponent (Topics/Actions in modern Copilots)
        if comp.get('kind') == 'DialogComponent':
            name = comp.get('schemaName') or comp.get('displayName')
            if name:
                dialog = comp.get('dialog', {})
                desc = dialog.get('modelDescription', '')
                
                tools.append({
                    "name": name,
                    "display_name": comp.get('displayName'),
                    "description": desc,
                    "bot_id": bot_id
                })
        
        # Support for older TaskDialog format (Standard Connectors)
        dialog = comp.get('dialog', {})
        if dialog.get('kind') == 'TaskDialog':
            action = dialog.get('action', {})
            op_id = action.get('operationId')
            if op_id:
                tools.append({
                    "name": op_id,
                    "display_name": dialog.get('modelDisplayName', op_id),
                    "description": dialog.get('modelDescription', ''),
                    "bot_id": bot_id
                })

    return tools

def main():
    parser = argparse.ArgumentParser(description="Flexible Copilot Studio tool extractor")
    parser.add_argument("--bots", nargs="+", default=DEFAULT_BOTS, help="List of Bot IDs")
    parser.add_argument("--environment", default=DEFAULT_ENV_ID, help="Environment ID")
    parser.add_argument("--output", default="all_tools.json", help="Output file")
    parser.add_argument("--cedar", default="generated_policy.cedar", help="Output Cedar policy file")
    
    args = parser.parse_args()
    
    all_tools = []
    for bot_id in args.bots:
        bot_tools = extract_for_bot(bot_id, args.environment)
        if bot_tools:
            all_tools.extend(bot_tools)

    # Write JSON
    with open(args.output, 'w') as f:
        json.dump(all_tools, f, indent=2)
    print(f"[+] Wrote {len(all_tools)} tools to {args.output}")

    # Generate Cedar Policy
    with open(args.cedar, 'w') as f:
        f.write("// Automatically generated Cedar policy for Copilot Studio\n")
        f.write("// Allows all extracted tools by default\n\n")
        
        seen = set()
        for tool in all_tools:
            key = (tool['bot_id'], tool['name'])
            if key in seen:
                continue
            seen.add(key)
            
            f.write(f"// Tool: {tool.get('display_name', tool['name'])} for Bot: {tool['bot_id']}\n")
            f.write(f"permit(\n")
            f.write(f"    principal,\n")
            f.write(f"    action == Action::\"tools/call\",\n")
            f.write(f"    resource\n")
            f.write(f") when {{\n")
            f.write(f"    resource == Resource::\"{tool['name']}\"\n")
            f.write(f"}};\n\n")
            
    print(f"[+] Generated Cedar policy at {args.cedar}")

if __name__ == "__main__":
    main()
