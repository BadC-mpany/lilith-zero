import json
import os
import re
import subprocess
import shutil
import sys

def sanitize_filename(text):
    """Remove non-alphanumeric characters for a clean filename."""
    return re.sub(r'[^a-zA-Z0-9]', '', text)

def deploy_connectors():
    # Paths configuration - relative to script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    master_file = os.path.join(script_dir, "enterprise-integrations.json")
    scaffolding_dir = os.path.join(script_dir, "scaffolding")
    temp_json_dir = os.path.join(script_dir, "split_connectors")
    
    # Target Environment: Default Directory (default)
    environment_id = "98e2f7d2-c1d3-4410-b87f-2396f157975f"

    print(f"[*] Starting deployment process for environment: {environment_id}")

    # 1. Switch to the target environment
    try:
        print(f"[*] Selecting environment {environment_id}...")
        subprocess.run(["pac", "org", "select", "--environment", environment_id], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error selecting environment: {e.stderr}")
        sys.exit(1)

    # 2. Initialize Scaffolding for NoAuth
    if os.path.exists(scaffolding_dir):
        shutil.rmtree(scaffolding_dir)
    os.makedirs(scaffolding_dir)
    
    print("[*] Initializing connector scaffolding (NoAuth)...")
    try:
        subprocess.run([
            "pac", "connector", "init", 
            "--connection-template", "NoAuth", 
            "--outputDirectory", scaffolding_dir
        ], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error initializing scaffolding: {e.stderr}")
        sys.exit(1)

    # 3. Read Master OpenAPI and Split
    if not os.path.exists(master_file):
        print(f"[!] Master file not found at {master_file}")
        sys.exit(1)

    with open(master_file, 'r') as f:
        master_data = json.load(f)

    if os.path.exists(temp_json_dir):
        shutil.rmtree(temp_json_dir)
    os.makedirs(temp_json_dir)

    deployed_tools = []
    paths = master_data.get('paths', {})
    
    print(f"[*] Found {len(paths)} paths in master file. Splitting...")

    for path, methods in paths.items():
        for method, details in methods.items():
            summary = details.get('summary', f"Tool {path}")
            filename = sanitize_filename(summary) + ".json"
            filepath = os.path.join(temp_json_dir, filename)

            # Create standalone OpenAPI v2 structure
            tool_json = {
                "swagger": "2.0",
                "info": {
                    "version": "1.0.0",
                    "title": summary,
                    "description": details.get('description', '')
                },
                "host": master_data.get('host'),
                "basePath": master_data.get('basePath'),
                "schemes": master_data.get('schemes'),
                "paths": {
                    path: {
                        method: details
                    }
                }
            }

            with open(filepath, 'w') as tf:
                json.dump(tool_json, tf, indent=2)

            # 4. Deploy Connector
            print(f"[*] Deploying {summary}...")
            max_retries = 2
            for attempt in range(max_retries):
                try:
                    result = subprocess.run([
                        "pac", "connector", "create",
                        "--api-definition-file", filepath,
                        "--api-properties-file", os.path.join(scaffolding_dir, "apiProperties.json")
                    ], capture_output=True, text=True, timeout=120)

                    output = (result.stdout or "") + (result.stderr or "")
                    
                    if result.returncode == 0:
                        print(f"    [+] Created: {summary}")
                        deployed_tools.append({"summary": summary, "status": "Created"})
                        break
                    elif "already exists in the org" in output:
                        print(f"    [-] Already Present: {summary} (Skipped)")
                        deployed_tools.append({"summary": summary, "status": "Already Present"})
                        break
                    elif "Failed to connect to Dataverse" in output and attempt < max_retries - 1:
                        print(f"    [!] Connection glitch, retrying {summary} (Attempt {attempt+2})...")
                        continue
                    else:
                        error_msg = result.stderr.strip() or result.stdout.strip()
                        summary_err = error_msg.split('\n')[0][:50] + "..." if len(error_msg) > 50 else error_msg
                        print(f"    [!] Failed: {summary} (Error: {summary_err})")
                        deployed_tools.append({"summary": summary, "status": "Failed"})
                        break
                except subprocess.TimeoutExpired:
                    print(f"    [!] Timeout: {summary} took too long to deploy.")
                    deployed_tools.append({"summary": summary, "status": "Timeout"})
                    break
                except Exception as e:
                    print(f"    [!] Unexpected Error: {str(e)}")
                    deployed_tools.append({"summary": summary, "status": "Error"})
                    break

    # 5. Output Results Table
    print("\n" + "="*50)
    print(f"{'Custom Connector Summary':<35} | {'Status':<10}")
    print("-" * 50)
    for tool in deployed_tools:
        print(f"{tool['summary']:<35} | {tool['status']:<10}")
    print("="*50)
    
    print("\n[!] IMPORTANT NEXT STEPS:")
    print("1. Open Microsoft Copilot Studio (PVA).")
    print("2. Navigate to your Copilot (e.g., 'otp_demo').")
    print("3. Go to 'Tools' -> 'Add Tool'.")
    print("4. Select your newly created Custom Connector.")
    print("5. Click 'Create Connection' (one-click initialization for NoAuth).")
    print("6. Your tool is now ready for use in the agent's planner.\n")

if __name__ == "__main__":
    deploy_connectors()
