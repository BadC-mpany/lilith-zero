import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

DIRECT_LINE_SECRET = os.getenv("DIRECT_LINE_SECRET")
BASE_URL = "https://directline.botframework.com/v3/directline"

def test_connection():
    if not DIRECT_LINE_SECRET:
        print("[!] DIRECT_LINE_SECRET missing from .env")
        return

    headers = {
        "Authorization": f"Bearer {DIRECT_LINE_SECRET}",
        "Content-Type": "application/json"
    }

    # 1. Start Conversation
    print("[*] 1. Starting Conversation...")
    res = requests.post(f"{BASE_URL}/conversations", headers=headers)
    if res.status_code not in [200, 201]:
        print(f"[!] Failed: {res.status_code}\n{res.text}")
        return
    
    data = res.json()
    conv_id = data["conversationId"]
    token = data["token"]
    print(f"[+] Success. Conv ID: {conv_id}")

    # 2. Send Hello
    print("\n[*] 2. Sending 'Hello'...")
    headers["Authorization"] = f"Bearer {token}"
    activity = {
        "type": "message",
        "from": {"id": "tester"},
        "text": "Hello"
    }
    res = requests.post(f"{BASE_URL}/conversations/{conv_id}/activities", headers=headers, json=activity)
    if res.status_code != 200:
        print(f"[!] Failed: {res.status_code}\n{res.text}")
        return
    print("[+] Activity sent.")

    # 3. Wait and Poll for response
    print("\n[*] 3. Polling for response (waiting 5s)...")
    import time
    time.sleep(5)
    res = requests.get(f"{BASE_URL}/conversations/{conv_id}/activities", headers=headers)
    if res.status_code != 200:
        print(f"[!] Failed: {res.status_code}\n{res.text}")
        return
    
    activities = res.json().get("activities", [])
    print(f"[+] Received {len(activities)} activities.")
    for act in activities:
        if act["from"]["id"] != "tester":
            print(f"\n[AGENT] > {act.get('text', '[No Text]')}")
            if "LatestPublishedVersionNotFound" in act.get('text', ''):
                print("\n[!] IMPORTANT: Your bot is NOT PUBLISHED.")
                print("[!] Go to Copilot Studio -> Publish -> Click the 'Publish' button.")
            return

    print("[?] No bot response found.")

if __name__ == "__main__":
    test_connection()
