#!/usr/bin/env python3
"""
Check if session files exist on Azure instance using Kudu API.
"""

import requests
import json
import base64
import os

# Azure credentials (you'll need these)
RESOURCE_GROUP = "lilith-zero-rg"
APP_NAME = "lilith-zero-webhook"
KUDU_URL = f"https://{APP_NAME}.scm.azurewebsites.net"

def get_kudu_credentials():
    """Get Kudu credentials from Azure CLI."""
    import subprocess
    try:
        result = subprocess.run(
            ["az", "webapp", "deployment", "list-publishing-profiles",
             "--resource-group", RESOURCE_GROUP,
             "--name", APP_NAME,
             "--query", "[0].userPWD",
             "-o", "tsv"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip()
    except Exception as e:
        print(f"Error getting credentials: {e}")
        return None

def check_session_files():
    """Check if session files exist on Azure."""
    password = get_kudu_credentials()
    if not password:
        print("Failed to get Kudu credentials")
        return False

    username = f"{APP_NAME}\\${APP_NAME}"

    # Check multiple possible session directories
    paths_to_check = [
        "/home/.lilith/sessions",
        "/home/site/wwwroot/.lilith/sessions",
        "/tmp/lilith-sessions"
    ]

    print(f"\nChecking Azure instance: {APP_NAME}")
    print(f"Kudu URL: {KUDU_URL}")
    print("=" * 70)

    for path in paths_to_check:
        try:
            print(f"\nChecking: {path}")

            # List files using Kudu API
            url = f"{KUDU_URL}/api/vfs{path}/"
            auth = (username, password)

            response = requests.get(url, auth=auth, timeout=10)

            if response.status_code == 200:
                files = response.json()
                if isinstance(files, list):
                    json_files = [f for f in files if f.get('name', '').endswith('.json')]
                    if json_files:
                        print(f"  ✓ Directory exists and contains {len(json_files)} session file(s)")
                        for f in json_files:
                            print(f"    - {f.get('name')} ({f.get('size', 0)} bytes)")

                            # Try to read the file content
                            file_url = f"{KUDU_URL}/api/vfs{path}/{f.get('name')}"
                            file_response = requests.get(file_url, auth=auth, timeout=10)
                            if file_response.status_code == 200:
                                try:
                                    content = json.loads(file_response.text)
                                    if 'taints' in content:
                                        print(f"      Taints: {content['taints']}")
                                    print(f"      Call count: {content.get('call_count', 'N/A')}")
                                except:
                                    print(f"      Content: {file_response.text[:100]}")
                    else:
                        print(f"  - Directory exists but no .json files (empty)")
                else:
                    print(f"  - Unexpected response format")
            elif response.status_code == 404:
                print(f"  ✗ Directory does not exist")
            else:
                print(f"  ? Got HTTP {response.status_code}")

        except Exception as e:
            print(f"  ! Error: {e}")

    print("\n" + "=" * 70)

if __name__ == "__main__":
    check_session_files()
