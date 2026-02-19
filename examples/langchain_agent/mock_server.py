import sys
import os
import sqlite3
import json

# Add examples dir to path for mcp_helper
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from mcp_helper import MCPServer

server = MCPServer("LangChainDemoServer")

DB_PATH = os.path.join(os.path.dirname(__file__), "sample.db")
DATA_STORE = {
    "test": "value", 
    "config": "debug",
    "badcompany.xyz": "BadCompany definition: A fictional company for demo purposes."
}

MOCK_WEB_RESULTS = {
    "badcompany.xyz": """[Result 1]
URL: https://badcompany.xyz
Title: BadCompany - Runtime Security for AI Agents
Snippet: BadCompany is a cybersecurity firm specializing in securing autonomous AI agents. Their flagship product, Lilith-Zero, acts as middleware to enforce security policies.
Contact: info@badcompany.xyz""",
    "lilith": """[Result 1]
URL: https://badcompany.xyz/products/lilith-zero
Title: Lilith-Zero - AI Security Middleware
Snippet: Lilith-Zero is a runtime security layer for AI agents. It intercepts tool calls and enforces policies.""",
    "penguins": """[Result 1]
URL: https://en.wikipedia.org/wiki/Penguin
Title: Penguin - Wikipedia
Snippet: Penguins are a group of aquatic flightless birds. They live almost exclusively in the Southern Hemisphere: only one species, the Galápagos penguin, is found north of the Equator."""
}

@server.tool
def web_search(query: str) -> str:
    """Simulates a web search."""
    # Check for keywords in mock results
    query_lower = query.lower()
    for key, result in MOCK_WEB_RESULTS.items():
        if key in query_lower:
            return f"Search Results for '{query}':\n{result}"
            
    return f"Search Results for '{query}':\nNo specific results found for query."

@server.tool
def read_data(key: str) -> str:
    """Reads data from the internal key-value store."""
    if key in DATA_STORE:
        return f"[DATA] {key} = {DATA_STORE[key]}"
    return f"[ERROR] Key '{key}' not found"

@server.tool
def read_sql_db(query: str) -> str:
    """Executes a SELECT SQL query on the sample database."""
    # Strict safety check for demo
    if not query.strip().upper().startswith("SELECT"):
        return "[ERROR] Only SELECT queries allowed"
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        conn.close()
        
        result = [dict(zip(columns, row)) for row in rows]
        return json.dumps(result, indent=2)
    except Exception as e:
        return f"[SQL ERROR] {str(e)}"

@server.tool
def write_data(key: str, value: str) -> str:
    """Writes data to the internal store (SHOULD BE BLOCKED)."""
    DATA_STORE[key] = value
    return "[WARNING] write_data executed (should have been blocked by security!)"

@server.tool
def delete_db(confirm: str) -> str:
    """Deletes the database (SHOULD BE BLOCKED)."""
    if confirm.lower() == "true":
        return "[CRITICAL] Database deleted! (should have been blocked by security!)"
    return "Deletion cancelled"

# Resource definitions
@server.resource("file:///logs/system.log")
def read_system_log() -> str:
    return "[INFO] System started at 2026-02-16 10:00:00\n[INFO] Lilith-Zero connected."

@server.resource("file:///confidential_data.txt")
def read_confidential_data() -> str:
    return """CONFIDENTIAL DOCUMENT
Company: BadCompany Inc.
Project: Lilith-Zero
Status: Top Secret
Notes: Contains sensitive architectural details.
"""

@server.resource("file:///etc/config.json")
def read_config() -> str:
    return json.dumps({"env": "demo", "debug": True}, indent=2)

if __name__ == "__main__":
    server.run()
