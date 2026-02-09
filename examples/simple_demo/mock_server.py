import sys
import os

# Add examples dir to path for mcp_helper
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from mcp_helper import MCPServer

server = MCPServer("MinimalServer")

@server.tool
def ping() -> str:
    """Simple health check."""
    return "pong"

@server.tool
def read_db(query: str) -> str:
    """Read data from the database (Restricted)."""
    return f"Data for query '{query}': [SECRET_DATA_123]"

if __name__ == "__main__":
    server.run()
