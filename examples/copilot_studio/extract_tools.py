import argparse
import os
import yaml
import json
import subprocess
import re

# Default Environment ID (can be overridden via --environment)
DEFAULT_ENV_ID = "98e2f7d2-c1d3-4410-b87f-2396f157975f"

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return None, result.stderr
        return result.stdout, None
    except Exception as e:
        return None, str(e)

def get_bot_ids(environment_id):
    print(f"[*] Listing copilots in environment {environment_id}...")
    cmd = f"dnx Microsoft.PowerApps.CLI.Tool --yes -- copilot list --environment {environment_id}"
    out, err = run_command(cmd)
    if not out:
        return []
    
    bot_ids = []
    # Regex to match GUIDs in the output
    guid_pattern = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
    
    for line in out.splitlines():
        if "Copilot ID" in line:
            continue
        matches = guid_pattern.findall(line)
        if matches:
            # The first UUID on a data line is usually the Copilot ID
            bot_ids.append(matches[0])
            
    return list(dict.fromkeys(bot_ids)) # Unique IDs

def extract_for_bot(bot_id, environment_id):
    temp_yaml = f"temp_{bot_id}.yaml"
    print(f"[*] Extracting template for bot {bot_id}...")
    
    # Try with templateVersion 1.0.0 as it is more stable for some bots
    cmd = (f"dnx Microsoft.PowerApps.CLI.Tool --yes -- copilot extract-template "
           f"--bot {bot_id} --environment {environment_id} --templateFileName {temp_yaml} --templateVersion 1.0.0 --overwrite")
    
    out, err = run_command(cmd)
    if out is None or not os.path.exists(temp_yaml):
        # Fallback to default if 1.0.0 fails
        print(f"[!] Extraction with 1.0.0 failed, trying default...")
        cmd_fallback = (f"dnx Microsoft.PowerApps.CLI.Tool --yes -- copilot extract-template "
                        f"--bot {bot_id} --environment {environment_id} --templateFileName {temp_yaml} --overwrite")
        out, err = run_command(cmd_fallback)
        
        if out is None or not os.path.exists(temp_yaml):
            print(f"[!] Failed to extract template for {bot_id}.")
            if err:
                print(f"    Error: {err.strip().splitlines()[-1] if err.strip() else 'Unknown'}")
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
    components = data.get('components', [])
    if isinstance(components, dict):
        components = [components]
    
    for comp in components:
        dialog = comp.get('dialog', {})
        # Robust filtering: only treat 'TaskDialog' as a tool. 
        # This excludes system topics like 'Greeting', 'Goodbye', etc.
        if dialog.get('kind') == 'TaskDialog':
            model_display_name = dialog.get('modelDisplayName')
            
            # Extract operationId (can be in several places depending on action type)
            op_id = dialog.get('operationId')
            if not op_id:
                action = dialog.get('action', {})
                op_id = action.get('operationId')
                if not op_id:
                    details = action.get('operationDetails', {})
                    op_id = details.get('operationId')
            
            schema_name = comp.get('schemaName')
            display_name = comp.get('displayName')
            
            tools.append({
                "name": schema_name or op_id or display_name,
                "display_name": model_display_name or display_name,
                "operation_id": op_id,
                "bot_id": bot_id
            })
            
    return tools

def main():
    parser = argparse.ArgumentParser(description="Robust Copilot Studio tool extractor")
    parser.add_argument("--bots", nargs="+", help="List of Bot IDs (auto-discovered if omitted)")
    parser.add_argument("--environment", default=DEFAULT_ENV_ID, help="Environment ID")
    parser.add_argument("--output", default="examples/copilot_studio/all_tools.json", help="Output file")
    parser.add_argument("--policy-dir", default="examples/copilot_studio/policies", help="Directory for multi-tenant Cedar policies")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.policy_dir):
        os.makedirs(args.policy_dir)
        print(f"[*] Created policy directory: {args.policy_dir}")
    
    bot_ids = args.bots
    if not bot_ids:
        bot_ids = get_bot_ids(args.environment)
        if not bot_ids:
            print("[!] No bots found or failed to list bots.")
            return

    print(f"[*] Processing {len(bot_ids)} bots: {bot_ids}")
    
    all_extracted_tools = []
    
    for bot_id in bot_ids:
        bot_tools = extract_for_bot(bot_id, args.environment)
        if bot_tools:
            all_extracted_tools.extend(bot_tools)
            
            # Generate Bot-Specific Cedar Policy
            policy_path = os.path.join(args.policy_dir, f"policy_{bot_id}.cedar")
            with open(policy_path, 'w') as f:
                f.write(f"// Automatically generated Cedar policy for Bot: {bot_id}\n")
                f.write("// Only includes actual Tools (Actions/Connectors), excluding system topics.\n\n")
                
                seen_in_bot = set()
                for tool in bot_tools:
                    tool_key = tool['name']
                    if tool_key in seen_in_bot:
                        continue
                    seen_in_bot.add(tool_key)
                    
                    resource_names = {tool['name']}
                    if tool.get('display_name'):
                        resource_names.add(tool['display_name'])
                    if tool.get('operation_id'):
                        resource_names.add(tool['operation_id'])
                    
                    # Add slugified and normalized versions to handle Copilot Studio webhook variations
                    additional_names = set()
                    for n in resource_names:
                        # Replace spaces with hyphens (common slugification)
                        additional_names.add(n.replace(" ", "-"))
                        # Remove spaces entirely
                        additional_names.add(n.replace(" ", ""))
                        # If it contains dots, take the last part
                        if "." in n:
                            additional_names.add(n.split(".")[-1])
                    
                    resource_names.update(additional_names)
                    
                    # Convert set to sorted list for deterministic output
                    names_list = sorted(list(resource_names))
                    
                    f.write(f"// Tool: {tool.get('display_name', tool['name'])}\n")
                    f.write(f"permit(\n")
                    f.write(f"    principal,\n")
                    f.write(f"    action in [Action::\"tools/call\", Action::\"resources/read\", Action::\"resources/write\"],\n")
                    f.write(f"    resource\n")
                    f.write(f") when {{\n")
                    
                    if len(names_list) == 1:
                        f.write(f"    resource == Resource::\"{names_list[0]}\"\n")
                    else:
                        names_condition = " || ".join([f"resource == Resource::\"{n}\"" for n in names_list])
                        f.write(f"    {names_condition}\n")
                        
                    f.write(f"}};\n\n")
            
            print(f"[+] Generated Cedar policy for bot {bot_id} at {policy_path}")

    with open(args.output, 'w') as f:
        json.dump(all_extracted_tools, f, indent=2)
    print(f"[*] Saved {len(all_extracted_tools)} total tools to {args.output}")

if __name__ == "__main__":
    main()
