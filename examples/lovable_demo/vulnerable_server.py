"""
Vulnerable MCP Server Simulation (Low-Level / Fast)
This server simulates a legacy production database service lacking inherent security controls.
Uses the project's internal mcp_helper for maximum compatibility with Lilith Zero.
"""

import sys
import os

# Add parent directory to path to find mcp_helper
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from mcp_helper import MCPServer

# Initialize the Server
server = MCPServer("Legacy Production Database")

# Simulated In-Memory Database
_DATABASE = {
    "users": [
        {"id": 1, "username": "admin", "email": "admin@corp.internal", "role": "superuser", "api_key": "sk_live_88374"},
        {"id": 2, "username": "jdoe", "email": "john.doe@corp.internal", "role": "editor", "api_key": "sk_live_99283"},
        {"id": 3, "username": "guest", "email": "guest@corp.internal", "role": "viewer", "api_key": "sk_live_11223"},
    ],
    "invoices": [
        {"id": 101, "user_id": 2, "amount": 5000.00, "status": "paid"},
        {"id": 102, "user_id": 3, "amount": 150.00, "status": "pending"},
    ]
}

@server.tool
def execute_sql(query: str) -> str:
    """
    Executes a raw SQL query against the production database.
    WARNING: No RLS or authorization is performed.
    """
    query = query.strip().lower()
    
    # Simulate SQL Execution Logic
    if "select *" in query:
        if "users" in query:
            return str(_DATABASE["users"])
        if "invoices" in query:
            return str(_DATABASE["invoices"])
            
    if "count" in query:
        if "users" in query:
            return f"Count: {len(_DATABASE['users'])}"
        if "invoices" in query:
            return f"Count: {len(_DATABASE['invoices'])}"

    return "Query executed successfully. (Simulated Response)"

@server.tool
def fetch_url(url: str) -> str:
    """
    Fetches content from an external URL.
    WARNING: Unrestricted outbound access.
    """
    return f"Successfully fetched content from: {url}"

if __name__ == "__main__":
    server.run()
