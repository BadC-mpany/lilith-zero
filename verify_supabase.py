import os
import httpx
import asyncio
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_PROJECT_URL")
SERVICE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
API_KEY = os.getenv("SENTINEL_API_KEY")

async def check():
    if not SUPABASE_URL or not SERVICE_KEY or not API_KEY:
        print("Missing env vars")
        return

    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/projects"
    params = {
        "api_key": f"eq.{API_KEY}",
        "select": "*"
    }
    headers = {
        "apikey": SERVICE_KEY,
        "Authorization": f"Bearer {SERVICE_KEY}"
    }

    print(f"Requesting: {url} with params {params}")
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params, headers=headers)
        print(f"Status: {resp.status_code}")
        # print(f"Body: {repr(resp.text)}")

        if resp.status_code == 200:
             data = resp.json()
             if not data:
                 print("No projects found for this API Key.")
             else:
                 print("Project found.")
                 print(f"Keys in response: {list(data[0].keys())}")
                 policies = data[0].get('policies')
                 print(f"Policies Type: {type(policies)}")
                 import json
                 with open("policies_dump.json", "w", encoding="utf-8") as f:
                     json.dump(policies, f, indent=2)
                 print("Policies dumped to policies_dump.json")
                 
                 # print(f"Policies Content: {repr(policies)}")
                 
                 tools = data[0].get('tools')
                 print(f"Tools Type: {type(tools)}")
                 print(f"Tools Content: {repr(tools)}")

if __name__ == "__main__":
    asyncio.run(check())
